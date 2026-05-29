<?php
/**
 * URL Checker v7 — Bug fixes + SSL cert detection + SSRF protection
 *
 * Major changes vs v6:
 *  - Phase 4 (SSL fallback + retry) sekarang PARALLEL via multiRun
 *  - Real retry loop sesuai maxRetry (bukan cuma 1x)
 *  - SSL certificate validity detection (sslInvalid flag)
 *  - SSRF protection: blacklist private/loopback IP + protocol whitelist
 *  - UTF-8 safe body slicing (mb_substr) + JSON_INVALID_UTF8_SUBSTITUTE
 *  - Handle dibuat PER chunk, bukan semua sekaligus (hindari fd exhaustion)
 *  - Header parsing untuk multi-block (redirect chain) → ambil response terakhir
 *  - WAF detection tidak lagi false-positive untuk Cloudflare CDN normal
 *  - curl_multi_select timeout 1.0s (bukan 50ms — hindari CPU thrashing)
 *  - Note error di-sanitasi (strip IP/path internal)
 *  - Body besar di-unset setelah ekstrak (hemat memory)
 */

while (ob_get_level()) ob_end_clean();
error_reporting(0);
ini_set('display_errors', 0);
ini_set('memory_limit', '512M');
set_time_limit(0);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// ── Input ─────────────────────────────────────────────────────────────────────
$input = json_decode(file_get_contents('php://input'), true);
if (!$input || !is_array($input)) { echo json_encode(['error' => 'Invalid JSON']); exit; }

$urls        = array_values(array_unique(array_filter(array_map('trim', (array)($input['urls']      ?? [])))));
$queries     = array_values(array_filter(array_map('trim', (array)($input['queries']   ?? []))));
$blacklist   = array_values(array_filter(array_map('trim', (array)($input['blacklist'] ?? []))));
$concurrency = max(1, min(100, (int)($input['concurrency'] ?? 50)));
$timeout     = max(1, min(30,  (int)($input['timeout']     ?? 5)));
$maxRetry    = max(0, min(3,   (int)($input['maxRetry']    ?? 1)));
$followRedir = (bool)($input['followRedirect'] ?? true);
$readSource  = (bool)($input['readSource']     ?? true);
$headFirst   = (bool)($input['headFirst']      ?? true);
$strictSsl   = (bool)($input['strictSsl']      ?? false);  // NEW: kalau true, cert invalid → error
$allowPrivate = (bool)($input['allowPrivate']  ?? false);  // NEW: izinkan private IP (untuk localhost/intranet testing)
$needScan    = !empty($queries) || !empty($blacklist);
$sourceLimit = $needScan
    ? max(5000,  min(100000, (int)($input['sourceLimit'] ?? 30000)))
    : 2000;

if (empty($urls))                  { echo json_encode(['error' => 'No URLs']); exit; }
if (!function_exists('curl_init')) { echo json_encode(['error' => 'cURL tidak tersedia']); exit; }

$UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36',
];
$uaCount = count($UA);

// ── SSRF GUARD ────────────────────────────────────────────────────────────────
// Block request ke private/loopback/link-local IP kecuali $allowPrivate=true
function isPrivateIp(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, 0.0.0.0/8
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
    return false;
}

function validateUrl(string $url, bool $allowPrivate): array {
    $parsed = parse_url($url);
    if (!$parsed || empty($parsed['host']) || empty($parsed['scheme'])) {
        return ['ok' => false, 'reason' => 'Invalid URL format'];
    }
    $scheme = strtolower($parsed['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') {
        return ['ok' => false, 'reason' => 'Only http/https allowed'];
    }
    if ($allowPrivate) return ['ok' => true];

    $host = $parsed['host'];
    // Resolve hostname → cek apakah private IP
    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips = [$host];
    } else {
        $records = @dns_get_record($host, DNS_A | DNS_AAAA);
        if ($records) {
            foreach ($records as $r) {
                if (!empty($r['ip']))   $ips[] = $r['ip'];
                if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
            }
        }
        // Fallback gethostbyname (IPv4 only) kalau dns_get_record gagal
        if (!$ips) {
            $resolved = gethostbyname($host);
            if ($resolved !== $host) $ips[] = $resolved;
        }
    }
    if (!$ips) return ['ok' => false, 'reason' => 'DNS resolution failed'];
    foreach ($ips as $ip) {
        if (isPrivateIp($ip)) return ['ok' => false, 'reason' => 'Private/loopback IP blocked (set allowPrivate=true)'];
    }
    return ['ok' => true];
}

// ── cURL handle factory ──────────────────────────────────────────────────────
function makeHandle(string $url, int $timeout, bool $followRedir, string $ua, bool $headOnly, bool $strictSsl): mixed {
    $ch = curl_init();
    if (!$ch) return false;
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_NOBODY         => $headOnly,
        CURLOPT_FOLLOWLOCATION => $followRedir,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => min(3, $timeout),
        CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
        CURLOPT_SSL_VERIFYPEER => $strictSsl,
        CURLOPT_SSL_VERIFYHOST => $strictSsl ? 2 : 0,
        CURLOPT_CERTINFO       => true,
        CURLOPT_SSLVERSION     => CURL_SSLVERSION_DEFAULT,
        CURLOPT_USERAGENT      => $ua,
        CURLOPT_ENCODING       => '',
        // SSRF hardening: hanya http/https, redirect juga dibatasi
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS=> CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_HTTPHEADER     => [
            'Accept: text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.5',
            'Connection: close',
        ],
    ]);
    return $ch;
}

function parseResp(mixed $ch, string|false $raw): array {
    $code        = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hSize       = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $cType       = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $finalUrl    = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $ms          = (int)round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
    $err         = curl_error($ch);
    $errno       = curl_errno($ch);
    $sslVerify   = (int)curl_getinfo($ch, CURLINFO_SSL_VERIFYRESULT);
    $headers     = $body = '';
    if ($raw !== false && $hSize > 0) {
        $headers = substr($raw, 0, $hSize);
        $body    = (string)substr($raw, $hSize);
    }
    return compact('code', 'headers', 'body', 'cType', 'finalUrl', 'ms', 'err', 'errno', 'sslVerify');
}

// ── multiRun: jalankan batch handle paralel ──────────────────────────────────
function multiRun(array $handles): array {
    $mh = curl_multi_init();
    curl_multi_setopt($mh, CURLMOPT_MAX_TOTAL_CONNECTIONS, 100);
    curl_multi_setopt($mh, CURLMOPT_MAXCONNECTS, 100);

    $added = [];
    foreach ($handles as $idx => $item) {
        if ($item['ch']) {
            curl_multi_add_handle($mh, $item['ch']);
            $added[$idx] = true;
        }
    }

    do { $mrc = curl_multi_exec($mh, $active); }
    while ($mrc === CURLM_CALL_MULTI_PERFORM);

    while ($active > 0 && $mrc === CURLM_OK) {
        // FIX v7: timeout 1.0s (bukan 50ms) → hindari CPU thrash
        if (curl_multi_select($mh, 1.0) === -1) usleep(100000);
        do { $mrc = curl_multi_exec($mh, $active); }
        while ($mrc === CURLM_CALL_MULTI_PERFORM);
    }

    $results = [];
    foreach ($handles as $idx => $item) {
        if (!$item['ch'] || !isset($added[$idx])) {
            $results[$idx] = [
                'code' => 0, 'headers' => '', 'body' => '', 'cType' => '',
                'finalUrl' => $item['url'] ?? '', 'ms' => 0,
                'err' => $item['preErr'] ?? 'curl_init failed',
                'errno' => 0, 'sslVerify' => 0,
            ];
            continue;
        }
        $results[$idx] = parseResp($item['ch'], curl_multi_getcontent($item['ch']));
        curl_multi_remove_handle($mh, $item['ch']);
        curl_close($item['ch']);
    }
    curl_multi_close($mh);
    return $results;
}

// ── Helper: bangun batch handle untuk daftar URL ─────────────────────────────
function buildHandles(array $urls, int $timeout, bool $followRedir, array $UA, int $uaCount, bool $headOnly, bool $strictSsl, array &$validation): array {
    $handles = [];
    foreach ($urls as $i => $url) {
        if (isset($validation[$i]) && !$validation[$i]['ok']) {
            $handles[$i] = ['ch' => false, 'url' => $url, 'preErr' => $validation[$i]['reason']];
            continue;
        }
        $ch = makeHandle($url, $timeout, $followRedir, $UA[$i % $uaCount], $headOnly, $strictSsl);
        $handles[$i] = ['ch' => $ch ?: false, 'url' => $url];
    }
    return $handles;
}

// ── Run multi-batch dengan chunking (handle dibuat PER chunk) ────────────────
function runBatched(array $urls, int $concurrency, int $timeout, bool $followRedir, array $UA, int $uaCount, bool $headOnly, bool $strictSsl, array $validation): array {
    $results = [];
    foreach (array_chunk($urls, $concurrency, true) as $chunk) {
        $handles = buildHandles($chunk, $timeout, $followRedir, $UA, $uaCount, $headOnly, $strictSsl, $validation);
        $results += multiRun($handles);
        unset($handles);
    }
    return $results;
}

// ── classifyStatus ───────────────────────────────────────────────────────────
function classifyStatus(int $code): string {
    if ($code === 0)                     return 'error';
    if ($code >= 200 && $code < 300)    return 'ok';
    if ($code >= 300 && $code < 400)    return 'redirect';
    if ($code === 401)                   return 'unauthorized';
    if ($code === 403)                   return 'forbidden';
    if ($code === 404 || $code === 410) return 'notfound';
    if ($code === 405)                   return 'method_not_allowed';
    if ($code === 429)                   return 'rate_limited';
    if ($code >= 500)                    return 'server_error';
    return 'other';
}

function findMatches(string $body, array $patterns): array {
    if (!$patterns || $body === '') return [];
    $lower    = strtolower($body);
    $found    = [];
    $notFound = count($patterns);
    foreach ($patterns as $p) {
        if ($p === '') continue;
        if (strpos($lower, strtolower($p)) !== false) {
            $found[] = $p;
            if (--$notFound === 0) break;
        }
    }
    return $found;
}

// ── WAF detection — refined: header doang TIDAK CUKUP ────────────────────────
// FIX v7: Cloudflare CDN normal jangan dianggap WAF block.
// WAF flag dipasang hanya kalau:
//   (a) body mengandung sig WAF block, ATAU
//   (b) header WAF + status code 403/406/418/429/503 (kemungkinan blocked)
function detectWaf(int $code, string $body, string $headers): bool {
    static $bodySigs = [
        'you have been blocked', 'your ip has been blocked', 'access has been denied',
        'attention required! | cloudflare', 'sorry, you have been blocked',
        'powered by incapsula', 'sucuri website firewall — access denied',
        'mod_security', 'access denied by ',
        'this site is protected by',
    ];
    static $hdrSigs = ['cf-ray:', 'x-sucuri-id:', 'x-iinfo:', 'x-protected-by:', 'x-sucuri-block:'];

    $bl = strtolower($body);
    foreach ($bodySigs as $s) { if (strpos($bl, $s) !== false) return true; }

    // Header sig hanya signal kalau status code tipikal block
    if (in_array($code, [403, 406, 418, 429, 503], true)) {
        $hl = strtolower($headers);
        foreach ($hdrSigs as $s) { if (strpos($hl, $s) !== false) return true; }
    }
    return false;
}

function isSslErr(int $errno, string $err): bool {
    // cURL error codes terkait SSL/TLS
    $sslErrnos = [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91];
    if (in_array($errno, $sslErrnos, true)) return true;
    if ($err === '') return false;
    foreach (['SSL', 'certificate', 'TLS', 'handshake', 'CAfile', 'CERT'] as $k) {
        if (stripos($err, $k) !== false) return true;
    }
    return false;
}

// FIX v7: sanitasi note error → strip IP & path lokal
function sanitizeNote(string $err): string {
    if ($err === '') return '';
    // Strip IPv4 dan IPv6
    $err = preg_replace('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', '<ip>', $err);
    $err = preg_replace('/\b[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+\b/', '<ipv6>', $err);
    // Strip path Windows & Unix
    $err = preg_replace('#[A-Z]:\\\\[^\s,;]+#', '<path>', $err);
    $err = preg_replace('#/(?:home|var|etc|opt|usr|root)/[^\s,;]+#', '<path>', $err);
    return substr($err, 0, 200);
}

// FIX v7: ambil block header response TERAKHIR (skip redirect chain headers)
function lastHeaderBlock(string $headers): string {
    if ($headers === '') return '';
    $headers = trim($headers);
    // Setiap response block dipisahkan oleh \r\n\r\n
    $blocks = preg_split('/\r\n\r\n/', $headers);
    if (!$blocks) return $headers;
    return end($blocks);
}

// FIX v7: UTF-8 safe slicing
function safeSlice(string $body, int $limit): string {
    if (strlen($body) <= $limit) return $body;
    if (function_exists('mb_substr') && mb_check_encoding($body, 'UTF-8')) {
        return mb_substr($body, 0, $limit, 'UTF-8');
    }
    // Fallback: byte slice + strip last potential incomplete UTF-8 sequence
    $sliced = substr($body, 0, $limit);
    // Trim trailing bytes yang potentially incomplete multi-byte
    while (strlen($sliced) > 0 && (ord($sliced[strlen($sliced) - 1]) & 0xC0) === 0x80) {
        $sliced = substr($sliced, 0, -1);
    }
    return $sliced;
}

// ═════════════════════════════════════════════════════════════════════════════
// VALIDASI URL (SSRF guard) di awal
// ═════════════════════════════════════════════════════════════════════════════
$validation = [];
foreach ($urls as $i => $url) {
    $validation[$i] = validateUrl($url, $allowPrivate);
}

// ═════════════════════════════════════════════════════════════════════════════
// FASE 1: HEAD/GET semua URL (bypass SSL untuk dapat content meski cert invalid)
// ═════════════════════════════════════════════════════════════════════════════
$headResults = runBatched($urls, $concurrency, $timeout, $followRedir, $UA, $uaCount, $headFirst, false, $validation);

// ═════════════════════════════════════════════════════════════════════════════
// FASE 2: Klasifikasi URL untuk tindakan lanjutan
// ═════════════════════════════════════════════════════════════════════════════
$needGet         = [];
$need405Get      = [];
$needSslFallback = [];
$needRetry       = [];

foreach ($headResults as $i => $hr) {
    if (isset($validation[$i]) && !$validation[$i]['ok']) continue;  // skip invalid URL

    $code  = $hr['code'];
    $err   = $hr['err'] ?? '';
    $errno = $hr['errno'] ?? 0;

    if ($code === 0 && isSslErr($errno, $err))   { $needSslFallback[$i] = $urls[$i]; continue; }
    if ($code === 0 && $maxRetry > 0)            { $needRetry[$i]       = $urls[$i]; continue; }
    if ($code === 405)                            { $need405Get[$i]      = $urls[$i]; continue; }
    if ($code >= 200 && $code < 300 && $readSource && $needScan) {
        $needGet[$i] = $urls[$i];
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// FASE 3: GET batch — paralel via multiRun
// ═════════════════════════════════════════════════════════════════════════════
$getResults    = !empty($needGet)    ? runBatched($needGet,    $concurrency, $timeout, $followRedir, $UA, $uaCount, false, false, $validation) : [];
$get405Results = !empty($need405Get) ? runBatched($need405Get, $concurrency, $timeout, $followRedir, $UA, $uaCount, false, false, $validation) : [];

// ═════════════════════════════════════════════════════════════════════════════
// FASE 4: SSL fallback (parallel) — https:// gagal → coba http://
// ═════════════════════════════════════════════════════════════════════════════
if (!empty($needSslFallback)) {
    $fbUrls = [];
    foreach ($needSslFallback as $i => $u) {
        if (stripos($u, 'https://') === 0) {
            $fbUrls[$i] = 'http://' . substr($u, 8);
        }
    }
    if ($fbUrls) {
        $fbResults = runBatched($fbUrls, $concurrency, $timeout, $followRedir, $UA, $uaCount, $headFirst, false, $validation);
        $fbGetTargets = [];
        foreach ($fbResults as $i => $fr) {
            if ($fr['code'] > 0) {
                $fr['sslFallback'] = true;
                $fr['fallbackUrl'] = $fbUrls[$i];
                $headResults[$i]   = $fr;
                if ($fr['code'] >= 200 && $fr['code'] < 300 && $readSource && $needScan) {
                    $fbGetTargets[$i] = $fbUrls[$i];
                }
            }
        }
        if ($fbGetTargets) {
            $fbGet = runBatched($fbGetTargets, $concurrency, $timeout, $followRedir, $UA, $uaCount, false, false, $validation);
            foreach ($fbGet as $i => $g) {
                if ($g['code'] > 0) $getResults[$i] = $g;
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// FASE 5: Retry (parallel) — sampai $maxRetry kali atau success
// ═════════════════════════════════════════════════════════════════════════════
$retryAttempts = 0;
$retryQueue    = $needRetry;
while (!empty($retryQueue) && $retryAttempts < $maxRetry) {
    $retryAttempts++;
    $retryResults = runBatched($retryQueue, $concurrency, $timeout + 3, $followRedir, $UA, $uaCount, $headFirst, false, $validation);
    $retryGetTargets = [];
    $stillFailing    = [];
    foreach ($retryResults as $i => $rr) {
        if ($rr['code'] > 0) {
            $rr['_retried']      = true;
            $rr['_retryAttempts'] = $retryAttempts;
            $headResults[$i]     = $rr;
            if ($rr['code'] >= 200 && $rr['code'] < 300 && $readSource && $needScan) {
                $retryGetTargets[$i] = $retryQueue[$i];
            }
        } else {
            $stillFailing[$i] = $retryQueue[$i];
            // Update note tapi tetap jadwalkan retry
            $headResults[$i]['err']   = $rr['err'];
            $headResults[$i]['errno'] = $rr['errno'];
        }
    }
    if ($retryGetTargets) {
        $retryGet = runBatched($retryGetTargets, $concurrency, $timeout, $followRedir, $UA, $uaCount, false, false, $validation);
        foreach ($retryGet as $i => $g) {
            if ($g['code'] > 0) $getResults[$i] = $g;
        }
    }
    $retryQueue = $stillFailing;
}

// ═════════════════════════════════════════════════════════════════════════════
// FASE 6: SSL CERT VALIDITY DETECTION (NEW) — only untuk URL HTTPS yang OK
// Pakai single extra strict-mode HEAD untuk cek cert validity tanpa tambahan
// overhead besar (hanya untuk URL yang HEAD-nya 2xx/3xx)
// ═════════════════════════════════════════════════════════════════════════════
$sslCheckTargets = [];
foreach ($urls as $i => $url) {
    if (isset($validation[$i]) && !$validation[$i]['ok']) continue;
    if (stripos($url, 'https://') !== 0) continue;  // only HTTPS
    $hr = $headResults[$i] ?? null;
    if (!$hr) continue;
    if (!empty($hr['sslFallback'])) continue;  // sudah jelas SSL bermasalah
    $code = (int)($hr['code'] ?? 0);
    if ($code < 200 || $code >= 500) continue;  // skip yang gagal/server error
    $sslCheckTargets[$i] = $url;
}

$sslCheckResults = [];
if ($sslCheckTargets) {
    // Strict mode: VERIFYPEER=true, VERIFYHOST=2 → kalau gagal handshake = cert invalid
    $sslCheckResults = runBatched(
        $sslCheckTargets, $concurrency, max(3, (int)($timeout / 2)),
        false, $UA, $uaCount, true, true, $validation
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// FASE 7: Assembly hasil akhir
// ═════════════════════════════════════════════════════════════════════════════
$results = [];
$stats   = [
    'total'        => count($urls),
    'ok'           => 0, 'match'        => 0, 'falsePositive' => 0,
    'forbidden'    => 0, 'notfound'     => 0, 'error'         => 0,
    'retried'      => 0, 'sslSkipped'   => 0, 'sslInvalid'    => 0,
    'waf'          => 0, 'headFallback' => 0, 'blocked'       => 0,
];

foreach ($urls as $i => $url) {
    // URL yang gagal validasi SSRF
    if (isset($validation[$i]) && !$validation[$i]['ok']) {
        $results[] = [
            'url'             => $url,
            'status'          => '—',
            'type'            => 'error',
            'ms'              => 0,
            'note'            => 'BLOCKED: ' . $validation[$i]['reason'],
            'matches'         => [], 'blacklisted' => [],
            'isFalsePositive' => false, 'isWafBlock' => false,
            'sslSkipped'      => false, 'sslInvalid' => false,
            'retried'         => false, 'serverInfo' => null,
            'source'          => null, 'sourceLength' => 0,
            'contentType'     => '', 'finalUrl' => null,
        ];
        $stats['blocked']++;
        $stats['error']++;
        continue;
    }

    $hr = $headResults[$i]   ?? ['code' => 0, 'err' => 'no response', 'errno' => 0, 'ms' => 0, 'headers' => '', 'body' => '', 'cType' => '', 'finalUrl' => $url, 'sslVerify' => 0];
    $gr = $getResults[$i]    ?? null;
    $g4 = $get405Results[$i] ?? null;
    $sc = $sslCheckResults[$i] ?? null;

    $active   = $gr ?? $g4 ?? $hr;
    $code     = (int)($active['code'] ?? 0);
    $ms       = (int)($active['ms'] ?? 0);
    $finalUrl = (string)($active['finalUrl'] ?? $url);
    $cType    = (string)($active['cType'] ?? '');
    $curlErr  = (string)($hr['err'] ?? '');
    $curlErrno = (int)($hr['errno'] ?? 0);

    // SSL cert detection
    $sslInvalid = false;
    $sslDetail  = null;
    if ($sc !== null) {
        // Kalau strict-mode handshake gagal, cert ada masalah
        $scErrno = (int)($sc['errno'] ?? 0);
        if ($sc['code'] === 0 && isSslErr($scErrno, (string)($sc['err'] ?? ''))) {
            $sslInvalid = true;
            $sslDetail  = sanitizeNote((string)($sc['err'] ?? 'SSL verification failed'));
        }
    }

    $rawHeaders = '';
    $body       = '';
    if ($gr) {
        $rawHeaders = $gr['headers'];
        $body       = safeSlice($gr['body'], $sourceLimit);
        unset($getResults[$i]['body']);  // hemat memory
    } elseif ($g4) {
        $rawHeaders = $g4['headers'];
        $body       = safeSlice($g4['body'], $sourceLimit);
        unset($get405Results[$i]['body']);
        $stats['headFallback']++;
    } else {
        $rawHeaders = $hr['headers'] ?? '';
    }

    $type    = classifyStatus($code);
    $matches = findMatches($body, $queries);
    $blHits  = findMatches($body, $blacklist);

    $isFP = ($type === 'ok') && !empty($blHits);
    if ($isFP) $type = 'false_positive';

    // FIX v7: WAF detection sekarang butuh body sig, atau header sig + status code blok
    $isWaf = ($type === 'ok' || $type === 'forbidden' || $type === 'rate_limited')
        && detectWaf($code, $body, $rawHeaders);

    // Parse server info hanya dari block header response TERAKHIR
    $serverInfo  = [];
    $finalHeader = lastHeaderBlock($rawHeaders);
    foreach (explode("\r\n", $finalHeader) as $hl) {
        if (preg_match('/^(Server|X-Powered-By|X-Generator|X-AspNet-Version):\s*(.+)$/i', $hl, $m)) {
            $serverInfo[strtolower($m[1])] = trim($m[2]);
        }
    }

    // Stats
    if ($type === 'ok' && !$isWaf) $stats['ok']++;
    if (!empty($matches) && $type !== 'false_positive') $stats['match']++;
    if ($isFP)  $stats['falsePositive']++;
    if (in_array($type, ['forbidden','unauthorized'])) $stats['forbidden']++;
    if ($type === 'notfound')   $stats['notfound']++;
    if ($type === 'error')      $stats['error']++;
    if (!empty($hr['_retried'])) $stats['retried']++;
    if (!empty($hr['sslFallback'])) $stats['sslSkipped']++;
    if ($sslInvalid) $stats['sslInvalid']++;
    if ($isWaf) $stats['waf']++;

    $sendSource = null;
    if ($readSource && $body !== '') {
        $sendSource = (!empty($matches) || !empty($blHits))
            ? $body
            : safeSlice($body, 500);
    }

    $results[] = [
        'url'             => $url,
        'status'          => $code > 0 ? $code : '—',
        'type'            => $type,
        'ms'              => $ms,
        'contentType'     => $cType,
        'finalUrl'        => ($finalUrl && $finalUrl !== $url) ? $finalUrl : null,
        'sourceLength'    => strlen($body),
        'source'          => $sendSource,
        'matches'         => $matches,
        'blacklisted'     => $blHits,
        'isFalsePositive' => $isFP,
        'isWafBlock'      => $isWaf,
        'sslSkipped'      => !empty($hr['sslFallback']),
        'sslInvalid'      => $sslInvalid,
        'sslDetail'       => $sslDetail,
        'fallbackUrl'     => $hr['fallbackUrl'] ?? null,
        'retried'         => !empty($hr['_retried']),
        'retryAttempts'   => $hr['_retryAttempts'] ?? 0,
        'serverInfo'      => $serverInfo ?: null,
        'note'            => $curlErr ? sanitizeNote($curlErr) : null,
    ];
}

unset($headResults, $getResults, $get405Results, $sslCheckResults);

echo json_encode(
    ['success' => true, 'count' => count($results), 'stats' => $stats, 'results' => $results],
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR
);

<?php
/**
 * URL Checker v6 — Semua 18 bug/issue diperbaiki
 * Fix: findMatches early-exit, GET code priority, retry→GET pipeline,
 *      CURLOPT conflict, multiRun partial failure, HEAD 405 fallback,
 *      WAF false positive, memory OOM, classifyStatus code-0, IPv4 force,
 *      source limit adaptif, note length limit
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
$needScan    = !empty($queries) || !empty($blacklist);
// FIX IMP-21: source limit adaptif
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

// ── FIX BUG-5: Tidak pakai CURLOPT_CUSTOMREQUEST — CURLOPT_NOBODY saja ──────
function makeHandle(string $url, int $timeout, bool $followRedir, string $ua, bool $headOnly): mixed {
    $ch = curl_init();
    if (!$ch) return false;
    curl_setopt_array($ch, [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_NOBODY         => $headOnly,   // HEAD=true, GET=false. Tidak pakai CUSTOMREQUEST.
        CURLOPT_FOLLOWLOCATION => $followRedir,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => min(3, $timeout),
        CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,  // FIX IMP-20: Force IPv4
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_SSLVERSION     => CURL_SSLVERSION_DEFAULT,
        CURLOPT_USERAGENT      => $ua,
        CURLOPT_ENCODING       => '',
        CURLOPT_HTTPHEADER     => [
            'Accept: text/html,application/xhtml+xml,*/*;q=0.8',
            'Accept-Language: en-US,en;q=0.5',
            'Connection: close',
        ],
        CURLOPT_FRESH_CONNECT  => false,
        CURLOPT_FORBID_REUSE   => false,
        CURLOPT_COOKIEFILE     => '',
    ]);
    return $ch;
}

function parseResp(mixed $ch, string|false $raw): array {
    $code     = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hSize    = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $cType    = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    $finalUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $ms       = (int)round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
    $err      = curl_error($ch);
    $headers  = $body = '';
    if ($raw !== false && $hSize > 0) {
        $headers = substr($raw, 0, $hSize);
        $body    = (string)substr($raw, $hSize);
    }
    return compact('code', 'headers', 'body', 'cType', 'finalUrl', 'ms', 'err');
}

// ── FIX ISSUE-6: multiRun() handle CURLM_CALL_MULTI_PERFORM dengan benar ────
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
        if (curl_multi_select($mh, 0.05) === -1) usleep(10000);
        do { $mrc = curl_multi_exec($mh, $active); }
        while ($mrc === CURLM_CALL_MULTI_PERFORM);
    }

    $results = [];
    foreach ($handles as $idx => $item) {
        if (!$item['ch'] || !isset($added[$idx])) {
            $results[$idx] = ['code' => 0, 'headers' => '', 'body' => '', 'cType' => '', 'finalUrl' => $item['url'], 'ms' => 0, 'err' => 'curl_init failed'];
            continue;
        }
        $results[$idx] = parseResp($item['ch'], curl_multi_getcontent($item['ch']));
        curl_multi_remove_handle($mh, $item['ch']);
        curl_close($item['ch']);
    }
    curl_multi_close($mh);
    return $results;
}

// ── FIX BUG-10: classifyStatus eksplisit handle code 0 ───────────────────────
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

// ── FIX BUG-1: findMatches early-exit benar ──────────────────────────────────
// Bug lama: $missing dikurangi tiap item yang KETEMU (salah logic).
// Fix: $notFound hanya dikurangi saat pattern DITEMUKAN → break saat 0.
function findMatches(string $body, array $patterns): array {
    if (!$patterns || $body === '') return [];
    $lower    = strtolower($body);
    $found    = [];
    $notFound = count($patterns);
    foreach ($patterns as $p) {
        if ($p === '') continue;
        if (strpos($lower, strtolower($p)) !== false) {
            $found[] = $p;
            if (--$notFound === 0) break; // semua ketemu → stop scan
        }
    }
    return $found;
}

// ── FIX ISSUE-8: WAF detection spesifik, tidak agresif ───────────────────────
function detectWaf(string $body, string $headers): bool {
    static $bodySigs = [
        'you have been blocked', 'your ip has been blocked',
        'blocked by cloudflare', 'cloudflare ray id',
        'powered by incapsula', 'sucuri website firewall',
        'mod_security', 'access denied by',
        'this site is protected by',
    ];
    static $hdrSigs = ['cf-ray:', 'x-sucuri-id:', 'x-iinfo:', 'x-protected-by:'];
    $bl = strtolower($body);
    $hl = strtolower($headers);
    foreach ($bodySigs as $s) { if (strpos($bl, $s) !== false) return true; }
    foreach ($hdrSigs  as $s) { if (strpos($hl, $s) !== false) return true; }
    return false;
}

function isSslErr(string $err): bool {
    if ($err === '') return false;
    foreach (['SSL', 'certificate', 'TLS', 'handshake', 'peer', 'CAfile', 'CERT'] as $k) {
        if (stripos($err, $k) !== false) return true;
    }
    return false;
}

function sslFallback(string $url, int $timeout, bool $followRedir, string $ua, bool $headOnly): ?array {
    if (stripos($url, 'https://') !== 0) return null;
    $httpUrl = 'http://' . substr($url, 8);
    $ch = makeHandle($httpUrl, $timeout, $followRedir, $ua, $headOnly);
    if (!$ch) return null;
    $parsed = parseResp($ch, curl_exec($ch));
    curl_close($ch);
    if ($parsed['code'] > 0) {
        $parsed['sslFallback'] = true;
        $parsed['fallbackUrl'] = $httpUrl;
        return $parsed;
    }
    return null;
}

// Helper: GET satu URL dan kembalikan parsed result
function doGet(string $url, int $timeout, bool $followRedir, string $ua): ?array {
    $ch = makeHandle($url, $timeout, $followRedir, $ua, false);
    if (!$ch) return null;
    $parsed = parseResp($ch, curl_exec($ch));
    curl_close($ch);
    return $parsed['code'] > 0 ? $parsed : null;
}

// ═══════════════════════════════════════════════════════════════════════════
// FASE 1: HEAD semua URL
// ═══════════════════════════════════════════════════════════════════════════
$headHandles = [];
foreach ($urls as $i => $url) {
    $ch = makeHandle($url, $timeout, $followRedir, $UA[$i % $uaCount], $headFirst);
    $headHandles[$i] = ['ch' => $ch ?: false, 'url' => $url];
}

$headResults = [];
foreach (array_chunk($headHandles, $concurrency, true) as $batch) {
    $headResults += multiRun($batch);
}
unset($headHandles);

// ═══════════════════════════════════════════════════════════════════════════
// FASE 2: Klasifikasi URL untuk tindakan lanjutan
// ═══════════════════════════════════════════════════════════════════════════
$needGet         = [];  // 2xx → GET baca source
$need405Get      = [];  // 405 → HEAD tidak support, coba GET
$needSslFallback = [];  // SSL error → coba http://
$needRetry       = [];  // network fail → retry

foreach ($headResults as $i => $hr) {
    $code = $hr['code'];
    $err  = $hr['err'] ?? '';

    if ($code === 0 && isSslErr($err)) { $needSslFallback[$i] = $urls[$i]; continue; }
    if ($code === 0 && $maxRetry > 0)  { $needRetry[$i]       = $urls[$i]; continue; }
    if ($code === 405)                  { $need405Get[$i]      = $urls[$i]; continue; }
    if ($code >= 200 && $code < 300 && $readSource && $needScan) {
        $needGet[$i] = $urls[$i];
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FASE 3: GET batch (source scan) — parallel multi-curl
// ═══════════════════════════════════════════════════════════════════════════
$getResults    = [];
$get405Results = [];

if (!empty($needGet)) {
    $getHandles = [];
    foreach ($needGet as $i => $url) {
        $ch = makeHandle($url, $timeout, $followRedir, $UA[$i % $uaCount], false);
        $getHandles[$i] = ['ch' => $ch ?: false, 'url' => $url];
    }
    foreach (array_chunk($getHandles, $concurrency, true) as $batch) {
        $getResults += multiRun($batch);
    }
    unset($getHandles);
}

// FIX IMP-16: GET untuk 405 — multi-curl juga
if (!empty($need405Get)) {
    $g405Handles = [];
    foreach ($need405Get as $i => $url) {
        $ch = makeHandle($url, $timeout, $followRedir, $UA[$i % $uaCount], false);
        $g405Handles[$i] = ['ch' => $ch ?: false, 'url' => $url];
    }
    foreach (array_chunk($g405Handles, $concurrency, true) as $batch) {
        $get405Results += multiRun($batch);
    }
    unset($g405Handles);
}

// ═══════════════════════════════════════════════════════════════════════════
// FASE 4: SSL fallback + Retry individual
// FIX BUG-3: Jika retry/ssl-fallback berhasil 2xx → GET untuk source
// ═══════════════════════════════════════════════════════════════════════════
foreach ($needSslFallback as $i => $url) {
    $fb = sslFallback($url, $timeout, $followRedir, $UA[$i % $uaCount], $headFirst);
    if ($fb) {
        $headResults[$i] = array_merge($headResults[$i] ?? [], $fb);
        if ($fb['code'] >= 200 && $fb['code'] < 300 && $readSource && $needScan) {
            $gr = doGet($fb['fallbackUrl'], $timeout, $followRedir, $UA[$i % $uaCount]);
            if ($gr) $getResults[$i] = $gr;
        }
    }
}

foreach ($needRetry as $i => $url) {
    $ch = makeHandle($url, $timeout + 3, $followRedir, $UA[$i % $uaCount], $headFirst);
    if (!$ch) continue;
    $parsed = parseResp($ch, curl_exec($ch));
    curl_close($ch);
    if ($parsed['code'] > 0) {
        $headResults[$i] = array_merge($headResults[$i] ?? [], $parsed, ['_retried' => true]);
        // FIX BUG-3: retry berhasil 2xx → GET baca source
        if ($parsed['code'] >= 200 && $parsed['code'] < 300 && $readSource && $needScan) {
            $gr = doGet($url, $timeout, $followRedir, $UA[$i % $uaCount]);
            if ($gr) $getResults[$i] = $gr;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FASE 5: Assembly hasil akhir
// FIX BUG-2: Prioritaskan code dari GET jika ada
// FIX BUG-4: Stats logic bersih
// ═══════════════════════════════════════════════════════════════════════════
$results = [];
$stats   = [
    'total'        => count($urls),
    'ok'           => 0, 'match'        => 0, 'falsePositive' => 0,
    'forbidden'    => 0, 'notfound'     => 0, 'error'         => 0,
    'retried'      => 0, 'sslSkipped'   => 0, 'waf'           => 0,
    'headFallback' => 0,
];

foreach ($urls as $i => $url) {
    $hr = $headResults[$i]   ?? ['code' => 0, 'err' => 'no response', 'ms' => 0, 'headers' => '', 'body' => '', 'cType' => '', 'finalUrl' => $url];
    $gr = $getResults[$i]    ?? null;
    $g4 = $get405Results[$i] ?? null;

    // FIX BUG-2: GET code lebih akurat dari HEAD
    $active   = $gr ?? $g4 ?? $hr;
    $code     = (int)($active['code'] ?? 0);
    $ms       = (int)($active['ms'] ?? 0);
    $finalUrl = (string)($active['finalUrl'] ?? $url);
    $cType    = (string)($active['cType'] ?? '');
    $curlErr  = (string)($hr['err'] ?? '');

    $rawHeaders = '';
    $body       = '';
    if ($gr) {
        $rawHeaders = $gr['headers'];
        $body       = substr($gr['body'], 0, $sourceLimit);
    } elseif ($g4) {
        $rawHeaders = $g4['headers'];
        $body       = substr($g4['body'], 0, $sourceLimit);
        $stats['headFallback']++;
    } else {
        $rawHeaders = $hr['headers'] ?? '';
    }

    // FIX BUG-10: classifyStatus handle code 0
    $type    = classifyStatus($code);
    $matches = findMatches($body, $queries);
    $blHits  = findMatches($body, $blacklist);

    // FIX BUG-4: cek isFP SEBELUM ubah $type, tidak double-check
    $isFP = ($type === 'ok') && !empty($blHits);
    if ($isFP) $type = 'false_positive';

    // FIX ISSUE-8: WAF hanya dicek saat type masih 'ok' (bukan false_positive)
    $isWaf = ($type === 'ok') && detectWaf($body, $rawHeaders);

    // Parse server info
    $serverInfo = [];
    foreach (explode("\r\n", $rawHeaders) as $hl) {
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
    if ($isWaf) $stats['waf']++;

    // FIX ISSUE-9: Kirim source penuh hanya jika ada match/bl hits
    // Jika tidak ada match, kirim preview 500 char saja untuk debug
    $sendSource = null;
    if ($readSource && $body !== '') {
        $sendSource = (!empty($matches) || !empty($blHits))
            ? $body
            : substr($body, 0, 500);
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
        'fallbackUrl'     => $hr['fallbackUrl'] ?? null,
        'retried'         => !empty($hr['_retried']),
        'serverInfo'      => $serverInfo ?: null,
        // FIX: batasi note 200 char agar tidak bocorkan path server
        'note'            => $curlErr ? substr($curlErr, 0, 200) : null,
    ];
}

// FIX ISSUE-9: unset sebelum encode untuk hemat memory
unset($headResults, $getResults, $get405Results);

echo json_encode(
    ['success' => true, 'count' => count($results), 'stats' => $stats, 'results' => $results],
    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
);
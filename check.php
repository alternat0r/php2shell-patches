<?php
/**
 * check.php — external patch-verification for CVE-2026-109618 / CVE-2026-109619
 *             (the "PHP2Shell" PHP core RCE).
 *
 * Usage:
 *     php check.php <domain-or-URL> [--insecure] [--json]
 *
 * Examples:
 *     php check.php your-domain.example
 *     php check.php https://your-domain.example/
 *     php check.php https://your-domain.example --json
 *
 * WHAT IT DOES
 *     Sends a single, ordinary HTTP(S) request (like a browser would) and reads
 *     the PHP version advertised in the `X-Powered-By` / `Server` response
 *     headers. It compares that version against the fixed releases and reports:
 *         PATCHED / VULNERABLE / UNKNOWN.
 *
 * WHAT IT DOES NOT DO
 *     It sends NO exploit payload — no `session.upload_progress` / multipart
 *     attack traffic, nothing that could crash or alter the target. It only
 *     reads version banners. It therefore cannot *exploit*-confirm the flaw;
 *     it confirms the deployed PHP version, which is what verifies a patch.
 *
 * LIMITATIONS
 *     - If the server hides its version (expose_php=Off, or a stripped Server
 *       header / proxy / CDN in front), the result is UNKNOWN. That is a GOOD
 *       hardening practice, not a failure — verify on the host with `php -v`.
 *     - A banner can be spoofed or stale; treat UNKNOWN/VULNERABLE as "verify
 *       on the server", and PATCHED as "consistent with a completed patch".
 *
 * AUTHORIZATION
 *     Run this only against hosts you own or are authorized to test.
 *
 * Exit codes: 0 = PATCHED, 1 = VULNERABLE, 2 = UNKNOWN, 3 = usage/connection error.
 */

// ---- fixed versions per branch (PHP security release 2026-10-21) ----------
const FIXED = [
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
];
// Branches 8.1 and earlier are end-of-life: no fix, always treated vulnerable.

// ---- parse args -----------------------------------------------------------
$args = array_slice($argv, 1);
$insecure = false;
$json = false;
$target = null;
foreach ($args as $a) {
    if ($a === '--insecure')      { $insecure = true; }
    elseif ($a === '--json')      { $json = true; }
    elseif ($a === '-h' || $a === '--help') { usage(0); }
    elseif (str_starts_with($a, '-')) { fwrite(STDERR, "Unknown option: $a\n"); usage(3); }
    else { $target = $a; }
}
if ($target === null) { usage(3); }

function usage(int $code): void {
    fwrite($code === 0 ? STDOUT : STDERR,
        "Usage: php check.php <domain-or-URL> [--insecure] [--json]\n" .
        "  Reads the PHP version banner over a normal HTTP request and compares\n" .
        "  it to the CVE-2026-109618/109619 fixed releases. Sends no exploit.\n");
    exit($code);
}

// ---- normalise target to a URL --------------------------------------------
$url = $target;
if (!preg_match('#^https?://#i', $url)) {
    $url = 'https://' . $url;   // default to https
}
$parts = parse_url($url);
if ($parts === false || empty($parts['host'])) {
    out_error("Could not parse a host from: $target");
}

// ---- perform a single benign request --------------------------------------
$headers = fetch_headers($url, $insecure);
if ($headers === null && stripos($url, 'https://') === 0) {
    // Fall back to http:// once, in case TLS isn't served.
    $url2 = 'http://' . substr($url, strlen('https://'));
    $headers = fetch_headers($url2, $insecure);
    if ($headers !== null) { $url = $url2; }
}
if ($headers === null) {
    out_error("Connection failed to {$parts['host']} (no HTTP response).");
}

/**
 * Do a lightweight request and return the response header lines, or null.
 * Prefers cURL; falls back to a streams-based HEAD/GET.
 */
function fetch_headers(string $url, bool $insecure): ?array {
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_NOBODY         => false,  // some servers omit X-Powered-By on HEAD
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_USERAGENT      => 'php-cve-2026-patch-check/1.0 (+banner read only)',
            CURLOPT_SSL_VERIFYPEER => !$insecure,
            CURLOPT_SSL_VERIFYHOST => $insecure ? 0 : 2,
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) { curl_close($ch); return null; }
        $hsize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);
        $raw = substr($resp, 0, $hsize);
        return preg_split('/\r?\n/', trim($raw));
    }

    // Streams fallback.
    $ctx = stream_context_create([
        'http' => ['method' => 'GET', 'timeout' => 20, 'follow_location' => 1, 'max_redirects' => 5,
                   'header' => "User-Agent: php-cve-2026-patch-check/1.0 (+banner read only)\r\n"],
        'ssl'  => ['verify_peer' => !$insecure, 'verify_peer_name' => !$insecure],
    ]);
    $fp = @fopen($url, 'r', false, $ctx);
    if ($fp === false) { return $http_response_header ?? null; }
    fclose($fp);
    return $http_response_header ?? null;
}

// ---- extract a PHP version from the headers --------------------------------
$banner = null;
$phpVersion = null;
foreach ($headers as $line) {
    if (preg_match('/^(X-Powered-By|Server):\s*(.+)$/i', $line, $m)) {
        if (preg_match('#PHP/(\d+\.\d+\.\d+)#i', $m[2], $vm)) {
            $phpVersion = $vm[1];
            $banner = trim($m[0]);
            break;
        }
        if ($banner === null) { $banner = trim($m[0]); } // keep for reporting
    }
}

// ---- evaluate --------------------------------------------------------------
$status = 'UNKNOWN';
$detail = '';
if ($phpVersion === null) {
    $status = 'UNKNOWN';
    $detail = "No PHP version in the response headers (expose_php likely Off, or a "
            . "proxy/CDN strips it). This is good hardening — verify on the host with `php -v`.";
} else {
    $branch = implode('.', array_slice(explode('.', $phpVersion), 0, 2));
    if (!isset(FIXED[$branch])) {
        $status = 'VULNERABLE';
        $detail = "PHP $phpVersion is on branch $branch, which is end-of-life and has no fix. "
                . "Migrate to a supported, patched branch.";
    } elseif (version_compare($phpVersion, FIXED[$branch], '>=')) {
        $status = 'PATCHED';
        $detail = "PHP $phpVersion >= fixed release " . FIXED[$branch] . " for branch $branch.";
    } else {
        $status = 'VULNERABLE';
        $detail = "PHP $phpVersion is below the fixed release " . FIXED[$branch] . " for branch $branch.";
    }
}

// ---- output ----------------------------------------------------------------
$result = [
    'target'      => $url,
    'php_version' => $phpVersion,
    'banner'      => $banner,
    'status'      => $status,
    'detail'      => $detail,
    'note'        => 'Banner-based check; no exploit sent. A banner can be spoofed or stale — '
                   . 'confirm on the server with `php -v` for authoritative results.',
];

if ($json) {
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
} else {
    $mark = ['PATCHED' => "\033[32m", 'VULNERABLE' => "\033[31m", 'UNKNOWN' => "\033[33m"][$status];
    $rst  = "\033[0m";
    echo "Target : {$result['target']}\n";
    echo "Banner : " . ($banner ?? '(none exposed)') . "\n";
    echo "PHP    : " . ($phpVersion ?? 'unknown') . "\n";
    echo "Status : {$mark}{$status}{$rst}\n";
    echo "Detail : {$detail}\n";
    echo "Note   : {$result['note']}\n";
}

exit(['PATCHED' => 0, 'VULNERABLE' => 1, 'UNKNOWN' => 2][$status]);

function out_error(string $msg): void {
    fwrite(STDERR, "Error: $msg\n");
    exit(3);
}

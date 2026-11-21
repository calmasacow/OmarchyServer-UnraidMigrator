<?php
declare(strict_types=1);

// This route requires Unraid's normal nginx WebGUI authorization AND PHP prepend.
// local_prepend.php validates native CSRF before dispatch and removes the token.
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('Content-Type: application/json; charset=utf-8');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('{"error":"POST required."}');
}
if (!function_exists('csrf_terminate') || !isset($_COOKIE[session_name()])) {
    http_response_code(403);
    exit('{"error":"Native WebGUI authorization required."}');
}
if (session_status() !== PHP_SESSION_ACTIVE && !@session_start(['read_and_close' => true])) {
    http_response_code(403);
    exit('{"error":"Native WebGUI authorization required."}');
}
$admin = isset($_SESSION['unraid_login']);
if (session_status() === PHP_SESSION_ACTIVE) session_write_close();
if (!$admin) {
    http_response_code(403);
    exit('{"error":"Native WebGUI authorization required."}');
}
if ($_POST !== [] || $_GET !== [] || $_FILES !== []) {
    http_response_code(400);
    exit('{"error":"This capture accepts no options."}');
}

try {
    require_once '/usr/local/libexec/omarchy-migration-export/host.php';
    $argv = ['/usr/bin/timeout', '-k', '1s', '15s', '/usr/bin/php', '-n', '-d', 'display_errors=0',
        '-d', 'memory_limit=64M', '/usr/local/libexec/omarchy-migration-export/export.php', 'bundle'];
    $result = \OmarchyExport\command($argv, 6 * (\OmarchyExport\REPORT_LIMIT + \OmarchyExport\JSON_LIMIT) + 4096, [0, 3]);
    $body = $result === null ? null : json_decode($result, true, 4);
    if (is_array($body) && is_string($body['error'] ?? null)) {
        http_response_code(422);
        exit($result);
    }
    if (!is_array($body) || !is_string($body['markdown'] ?? null) || !is_string($body['json'] ?? null)) {
        throw new RuntimeException('capture unavailable');
    }
    echo $result;
} catch (Throwable) {
    http_response_code(503);
    echo '{"error":"Capture failed or timed out. No files were saved."}';
}

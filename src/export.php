<?php
declare(strict_types=1);

namespace OmarchyExport;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/host.php';

$format = $argv[1] ?? '';
if ($argc !== 2 || !in_array($format, ['json', 'markdown', 'bundle'], true)) {
    fwrite(STDERR, "Usage: php export.php json|markdown|bundle (stdout only)\n");
    exit(2);
}
try {
    $out = capture(new HostProbe(), $format === 'json' ? null : static fn() => inventoryMarkdown(hostInventory()));
    echo $format === 'bundle' ? json_encode($out, JSON_THROW_ON_ERROR) : $out[$format];
} catch (ExportError $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    if ($format === 'bundle') echo json_encode(['error' => $e->getMessage()], JSON_THROW_ON_ERROR);
    exit(3);
} catch (\Throwable) {
    fwrite(STDERR, "Migration export failed; no output emitted.\n");
    exit(1);
}

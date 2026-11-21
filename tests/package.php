<?php
declare(strict_types=1);

require __DIR__ . '/../src/collector.php';

function requireThat(bool $condition): void
{
    if (!$condition) throw new RuntimeException('Package validation failed');
}

$doc = new DOMDocument();
requireThat($argc === 2 && $doc->load($argv[1], LIBXML_NONET));
$root = $doc->documentElement;
requireThat($root->nodeName === 'PLUGIN' && $root->getAttribute('name') === 'omarchy-migration-export');
requireThat($root->getAttribute('version') === \OmarchyExport\VERSION && $root->getAttribute('min') === '7.3.4');
requireThat($doc->doctype === null && $doc->getElementsByTagName('URL')->length === 0);
$cli = '/usr/local/libexec/omarchy-migration-export';
$web = '/usr/local/emhttp/plugins/omarchy-migration-export';
$expected = ["$cli/collector.php", "$cli/inventory.php", "$cli/host.php", "$cli/export.php", "$web/OmarchyMigrationExport.page", "$web/capture.php"];
$entries = $doc->getElementsByTagName('FILE');
requireThat($entries->length === count($expected) + 1);
foreach ($expected as $i => $target) {
    $file = $entries->item($i);
    requireThat($file->getAttribute('Name') === $target && $file->getAttribute('Mode') === '0644' && $file->getAttribute('Type') === 'base64');
    requireThat(!$file->hasAttribute('Run') && !$file->hasAttribute('Method'));
    $bytes = base64_decode($file->getElementsByTagName('INLINE')->item(0)->textContent, true);
    requireThat(is_string($bytes) && $bytes === file_get_contents(__DIR__ . '/../src/' . basename($target)));
    requireThat(hash('sha256', $bytes) === $file->getElementsByTagName('SHA256')->item(0)->textContent);
}
$remove = $entries->item(count($expected));
requireThat($remove->getAttribute('Method') === 'remove' && $remove->getAttribute('Run') === '/bin/sh');
$script = trim($remove->getElementsByTagName('INLINE')->item(0)->textContent);
$lines = array_map(static fn(string $path): string => 'rm -f -- ' . escapeshellarg($path), $expected);
requireThat($script === implode("\n", ['set -eu', ...$lines, "rmdir -- '$web' '$cli' 2>/dev/null || :"]));
echo "Local .plg XML, six embedded files, checksums and removal scope verified\n";

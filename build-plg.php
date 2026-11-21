<?php
declare(strict_types=1);

require __DIR__ . '/src/collector.php';

if (PHP_SAPI !== 'cli' || $argc !== 1) exit(2);
$name = 'omarchy-migration-export';
$version = \OmarchyExport\VERSION;
$web = '/usr/local/emhttp/plugins/' . $name;
$cli = '/usr/local/libexec/' . $name;
$files = [
    'collector.php' => "$cli/collector.php", 'inventory.php' => "$cli/inventory.php", 'host.php' => "$cli/host.php", 'export.php' => "$cli/export.php",
    'OmarchyMigrationExport.page' => "$web/OmarchyMigrationExport.page", 'capture.php' => "$web/capture.php",
];
$xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
$xml .= "<PLUGIN name=\"$name\" version=\"$version\" min=\"7.3.4\">\n";
foreach ($files as $source => $target) {
    $data = file_get_contents(__DIR__ . '/src/' . $source);
    if ($data === false) exit(1);
    $xml .= "  <FILE Name=\"$target\" Type=\"base64\" Mode=\"0644\"><INLINE>\n";
    $xml .= chunk_split(base64_encode($data), 76, "\n");
    $xml .= '  </INLINE><SHA256>' . hash('sha256', $data) . "</SHA256></FILE>\n";
}
$xml .= '  <FILE Method="remove" Run="/bin/sh"><INLINE><![CDATA[' . "\nset -eu\n";
foreach ($files as $target) $xml .= 'rm -f -- ' . escapeshellarg($target) . "\n";
$xml .= "rmdir -- '$web' '$cli' 2>/dev/null || :\n";
$xml .= "  ]]></INLINE></FILE>\n</PLUGIN>\n";
echo $xml;

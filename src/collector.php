<?php
declare(strict_types=1);

namespace OmarchyExport;

const VERSION = '2026.11.21.1';
const LIMIT = 256;
const JSON_LIMIT = 60 * 1024;
const REPORT_LIMIT = 256 * 1024;
const SCOPE_ERROR = 'Inventory exceeds the v1 export limits. Review a smaller scope offline; no incomplete manifest was emitted.';

final class ExportError extends \RuntimeException {}

interface Probe
{
    public function state(): ?string;
    public function shareNames(): ?array;
    public function mountInfo(): ?string;
    public function liveShares(): ?string;
    public function security(string $protocol): ?string;
    public function pools(): ?string;
    public function blockDevices(): ?string;
    public function shareLink(string $name): ?string;
    public function directory(string $path): ?array;
}

function matches(string $pattern, ?string $value): bool
{
    return $value !== null && preg_match($pattern, $value) === 1;
}

function nameOk(string $value): bool
{
    return $value === trim($value) && matches('/\A[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,79}\z/D', $value);
}

function pathOk(string $value): bool
{
    // Intentionally narrower than the importer. No markup, controls, or dot segments.
    return strlen($value) <= 4096 && matches('~\A(?:/[A-Za-z0-9_.:()+ -]+)+\z~D', $value)
        && !preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $value);
}

function iniFields(?string $text, bool $sections = false): array
{
    if ($text === null) return [];
    $data = @parse_ini_string($text, $sections, INI_SCANNER_RAW);
    return is_array($data) ? $data : [];
}

function field(array $row, string $key, string $pattern): ?string
{
    $value = $row[$key] ?? null;
    return is_string($value) && matches($pattern, $value) ? $value : null;
}

function unescapeMount(string $s): string
{
    return strtr($s, ['\\040' => ' ', '\\011' => "\t", '\\012' => "\n", '\\134' => '\\']);
}

function mountRows(?string $input): ?array
{
    if ($input === null || $input === '' || !str_ends_with($input, "\n")) return null;
    $rows = [];
    foreach (explode("\n", rtrim($input, "\n")) as $line) {
        $parts = explode(' - ', $line, 2);
        if (count($parts) !== 2) return null;
        $pre = explode(' ', $parts[0]);
        $post = explode(' ', $parts[1]);
        if (count($pre) < 6 || count($post) !== 3 || !matches('/\A\d+:\d+\z/', $pre[2])) return null;
        $path = unescapeMount($pre[4]);
        if ($path !== '/' && $path !== '/mnt' && !str_starts_with($path, '/mnt/')) continue;
        $rows[$path][] = [
            'id' => $pre[0], 'parent' => $pre[1],
            'dev' => $pre[2], 'root' => unescapeMount($pre[3]), 'fs' => $post[0],
            'source' => unescapeMount($post[1]), 'ro' => in_array('ro', explode(',', $pre[5]), true),
        ];
        if (count($rows) > LIMIT) throw new ExportError(SCOPE_ERROR);
    }
    ksort($rows, SORT_STRING);
    return $rows;
}

function poolRows(?string $text): array
{
    $out = [];
    foreach (explode("\n", trim($text ?? '')) as $line) {
        $columns = explode("\t", $line);
        if (count($columns) !== 3) continue;
        [$pool, $guid, $health] = $columns;
        if (!matches('/\A[A-Za-z][A-Za-z0-9_.:-]{0,254}\z/', $pool)) continue;
        $validGuid = matches('/\A[1-9][0-9]{0,19}\z/', $guid)
            && (strlen($guid) < 20 || strcmp($guid, '18446744073709551615') <= 0);
        $out[$pool][] = [$validGuid ? $guid : null,
            in_array($health, ['ONLINE', 'DEGRADED', 'FAULTED', 'OFFLINE', 'UNAVAIL', 'REMOVED', 'SUSPENDED'], true) ? $health : 'unknown'];
    }
    return $out;
}

function blockRows(?string $text): array
{
    $doc = json_decode($text ?? '', true, 8);
    $out = [];
    foreach (is_array($doc['blockdevices'] ?? null) ? $doc['blockdevices'] : [] as $row) {
        if (!is_array($row)) continue;
        $dev = field($row, 'maj:min', '/\A\d+:\d+\z/');
        if ($dev !== null) $out[$dev][] = $row;
    }
    return $out;
}

function below(string $path, string $parent): bool
{
    return str_starts_with($path, $parent . '/');
}

function inventory(Probe $probe, ?string $mountText, array &$notes): array
{
    $rows = mountRows($mountText);
    if ($rows === null) return [[], [], null];
    // Unraid can bind /mnt onto itself. Only ignore the ancestor when
    // mountinfo proves it is the same subtree of the visible root filesystem.
    $root = count($rows['/'] ?? []) === 1 ? $rows['/'][0] : null;
    $mnt = count($rows['/mnt'] ?? []) === 1 ? $rows['/mnt'][0] : null;
    $selfBind = $root !== null && $mnt !== null && $root['root'] === '/' && $mnt['root'] === '/mnt'
        && $mnt['parent'] === $root['id'] && $mnt['dev'] === $root['dev']
        && $mnt['fs'] === $root['fs'] && $mnt['source'] === $root['source'];
    unset($rows['/']);
    $pools = $blocks = null;
    $mounts = $excluded = [];
    foreach ($rows as $path => $at) {
        // Ignore the aggregate view (not a migration filesystem) and its descendants.
        if (preg_match('~\A/mnt/user0?(?:/|$)~', $path) || $path === '/mnt') continue;
        $rootCandidate = pathOk($path) && matches('~\A/mnt/(?:disks/)?[^/]+\z~D', $path)
            && !in_array($path, ['/mnt/disks', '/mnt/remotes', '/mnt/rootshare', '/mnt/addons'], true);
        $row = $at[0];
        $reason = 'Not an unambiguous, supported physical mount root.';
        $health = null;
        $identity = [];
        $ambiguous = false;
        foreach ($rows as $other => $entriesAt) {
            // Other ancestor mounts still make the backing namespace ambiguous.
            if (below($path, $other) && !($other === '/mnt' && $selfBind)) $ambiguous = true;
            foreach ($entriesAt as $entry) {
                if ($other !== $path && $entry['fs'] === $row['fs'] && $entry['dev'] === $row['dev']) $ambiguous = true;
            }
        }
        if ($rootCandidate && count($at) === 1 && !$ambiguous && $row['root'] === '/') {
            if ($row['fs'] === 'zfs' && strlen($row['source']) <= 255
                && matches('~\A[A-Za-z][A-Za-z0-9_.:-]*(?:/[A-Za-z0-9_.: -]+)*\z~D', $row['source'])) {
                $pools ??= poolRows($probe->pools());
                $entries = $pools[explode('/', $row['source'])[0]] ?? [];
                [$guid, $health] = count($entries) === 1 ? $entries[0] : [null, 'unknown'];
                if ($guid !== null && $health === 'ONLINE') $identity = ['dataset' => $row['source'], 'poolGuid' => $guid];
                else $reason = 'ZFS pool is not verified ONLINE with a valid GUID.';
            } elseif ($row['fs'] === 'exfat') {
                $blocks ??= blockRows($probe->blockDevices());
                $entries = $blocks[$row['dev']] ?? [];
                $device = count($entries) === 1 ? $entries[0] : [];
                $uuid = field($device, 'uuid', '/\A[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\z/D');
                $source = field($device, 'path', '~\A/dev/[A-Za-z0-9_.-]+\z~D');
                $sameUuid = 0;
                foreach ($blocks as $devicesAt) foreach ($devicesAt as $d) {
                    if ($uuid !== null && is_string($d['uuid'] ?? null) && strcasecmp($uuid, $d['uuid']) === 0) ++$sameUuid;
                }
                if ($sameUuid === 1 && $source !== null && $source === $row['source'] && ($device['fstype'] ?? null) === 'exfat') {
                    $identity = ['uuid' => $uuid];
                } else $reason = 'exFAT device and filesystem UUID could not be verified.';
            } elseif (!in_array($row['fs'], ['zfs', 'exfat'], true)) $reason = 'Filesystem is unsupported by the v1 preview.';
        }
        $kind = in_array($row['fs'], ['zfs', 'exfat', 'btrfs', 'xfs', 'ext4', 'ntfs3', 'vfat'], true) ? $row['fs'] : 'other';
        $label = pathOk($path) ? "`$path`" : '(path omitted)';
        $detail = $kind . ($health === null ? '' : "; pool health $health") . (count($at) === 1 ? ($row['ro'] ? '; source ro' : '; source rw') : '; stacked mounts');
        if (!$identity) {
            $entry = ['name' => 'Storage ' . (count($excluded) + 1), 'reason' => $reason];
            if (pathOk($path)) $entry['path'] = $path;
            $excluded[] = $entry;
            $notes[] = "- $label — $detail; excluded. $reason";
            continue;
        }
        $id = 'fs-' . substr(hash('sha256', $row['fs'] . "\0" . implode("\0", $identity) . "\0" . $path), 0, 32);
        $mounts[$path] = ['id' => $id, 'path' => $path, 'fsType' => $row['fs']] + $identity;
        $verified = $row['fs'] === 'zfs' ? "dataset `{$identity['dataset']}`, pool GUID `{$identity['poolGuid']}`" : "UUID `{$identity['uuid']}`";
        $notes[] = "- $label — $detail; $verified. Same-path rehearsal candidate, not destination evidence.";
    }
    return [$mounts, $excluded, $rows];
}

function capture(Probe $probe): array
{
    $state = iniFields($probe->state());
    $array = field($state, 'mdState', '/\A(?:STARTED|STOPPED)\z/D') ?? 'unknown or transitioning';
    $active = $array === 'STARTED';
    $host = field($state, 'NAME', '/\A[A-Za-z0-9][A-Za-z0-9.-]{0,79}\z/D') ?? 'unavailable';
    $version = field($state, 'version', '/\A[0-9][0-9.]{0,20}(?:[-+][A-Za-z0-9.-]{1,24})?\z/D') ?? 'unavailable';
    $notes = [];
    $names = $probe->shareNames();
    $live = $active ? $probe->liveShares() : null;
    $liveRows = iniFields($live, true);
    $access = $active ? [
        'smb' => iniFields($probe->security('smb'), true),
        'nfs' => iniFields($probe->security('nfs'), true),
    ] : [];
    $mountText = $active ? $probe->mountInfo() : null;
    [$mounts, $exclusions, $rows] = $active ? inventory($probe, $mountText, $notes) : [[], [], null];
    $namesAll = array_unique(array_merge($names ?? [], array_map('strval', array_keys($liveRows))));
    if (count($namesAll) > LIMIT) throw new ExportError(SCOPE_ERROR);
    sort($namesAll, SORT_STRING);
    $seen = [];
    foreach ($namesAll as $name) $seen[strtolower($name)] = ($seen[strtolower($name)] ?? 0) + 1;
    $shares = $shareNotes = [];
    $omitted = 0;
    foreach ($namesAll as $name) {
        if (!nameOk($name) || $seen[strtolower($name)] !== 1) { ++$omitted; continue; }
        $reason = !$active ? 'Array not confirmed started; saved share name only.'
            : 'Exclusive backing not verified; share may be split, offline, or unsupported.';
        $row = $liveRows[$name] ?? [];
        $row = is_array($row) ? $row : [];
        $selected = null;
        $dir = null;
        $mode = null;
        if ($rows !== null && count($rows['/mnt/user'] ?? []) === 1
            && $rows['/mnt/user'][0]['fs'] === 'fuse.shfs' && $rows['/mnt/user'][0]['root'] === '/'
            && ($row['exclusive'] ?? null) === 'yes') {
            $link = $probe->shareLink($name);
            if ($link !== null && pathOk($link) && basename($link) === $name) {
                $mount = $mounts[dirname($link)] ?? null;
                $blocked = false;
                foreach ($rows as $path => $_) {
                    if ($path === $link || below($path, $link) || $path === '/mnt/user/' . $name || below($path, '/mnt/user/' . $name)) $blocked = true;
                }
                if ($mount !== null && !$blocked) {
                    $dir = $probe->directory($link);
                    if ($dir !== null) {
                        $mode = sprintf('%04o', $dir['mode'] & 07777);
                        $selected = ['name' => $name, 'mount' => $mount['id'], 'path' => $link,
                            'legacyPath' => '/mnt/user/' . $name, 'review' => 'manual-review',
                            'reason' => 'Verify destination read-only access and share permissions before migration.'];
                    } else $reason = 'Backing share root is not a verified directory.';
                } else $reason = 'Exclusive link does not resolve directly to an eligible mount, or the share contains another mount.';
            }
        }
        $shares[] = $selected ?? ['name' => $name, 'review' => 'deferred', 'reason' => $reason];
        $security = [];
        foreach (['smb' => 'SMB', 'nfs' => 'NFS'] as $prefix => $label) {
            $settings = $access[$prefix][$name] ?? [];
            $settings = is_array($settings) ? $settings : [];
            $export = field($settings, 'export', '/\A(?:e|eh|et|eth|-)\z/D') ?? 'unknown';
            $modeSetting = field($settings, 'security', '/\A(?:public|secure|private)\z/D') ?? 'unknown';
            $security[] = "$label export $export, access $modeSetting";
        }
        $tier = field($row, 'useCache', '/\A(?:no|yes|only|prefer)\z/D') ?? 'unknown';
        $pool1 = field($row, 'cachePool', '/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\z/D') ?? 'not recorded';
        $pool2 = field($row, 'cachePool2', '/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\z/D') ?? 'not recorded';
        $shareNotes[] = "- `$name` — " . ($selected === null ? "deferred: $reason" : sprintf(
            'candidate `%s` (legacy `%s`); source UID:GID %d:%d, mode %s.',
            $selected['path'], $selected['legacyPath'], $dir['uid'], $dir['gid'], $mode
        )) . ($active ? ' Runtime settings (not effective access): ' . implode('; ', $security) . "; useCache $tier; pool fields `$pool1`, `$pool2`. ACLs and rules not collected." : '');
    }
    if ($omitted) $exclusions[] = ['name' => 'Unrepresentable share names', 'reason' => "$omitted share names could not be represented uniquely and safely in v1."];
    if (!$active || $rows === null) $exclusions[] = ['name' => 'Unverified source storage', 'reason' => $active
        ? 'Mount table unavailable or invalid.' : 'Array not confirmed started; no storage probes were run.'];
    if ($names === null) $exclusions[] = ['name' => 'Saved share inventory', 'reason' => 'Saved share directory unavailable.'];
    if ($active) {
        // Do not issue further active probes if the array stopped during capture.
        $end = field(iniFields($probe->state()), 'mdState', '/\ASTARTED\z/D');
        if ($end === null || $mountText !== $probe->mountInfo() || $live !== $probe->liveShares()) {
            throw new ExportError('Source state changed during capture; no export emitted. Retry once the source is stable.');
        }
    }
    $manifest = ['version' => 1, 'mounts' => array_values($mounts), 'shares' => $shares, 'exclusions' => $exclusions,
        'metadata' => [
            ['id' => 'Docker inventory', 'kind' => 'docker-inspect', 'deferReason' => 'Workload collection is not implemented; Docker was not queried.'],
            ['id' => 'VM inventory', 'kind' => 'vm-xml', 'deferReason' => 'Workload collection is not implemented; libvirt was not queried.'],
        ]];
    $summary = sprintf('Array: %s. %d mount candidate(s), %d deferred share(s), %d exclusion(s).',
        $array, count($mounts), count(array_filter($shares, static fn(array $s): bool => $s['review'] === 'deferred')), count($exclusions));
    $report = implode("\n", array_merge([
        '# Unraid → Omarchy migration review', '', 'Private infrastructure inventory. Not an apply request.', '',
        '- Source: ' . $host . '; Unraid: ' . $version . '; collector: ' . VERSION . '; captured UTC: ' . gmdate('Y-m-d\TH:i:s\Z'),
        '- ' . $summary,
        '- Storage: ' . ($rows === null ? 'unavailable; array not started or mount evidence unavailable.' : 'partial; eligible mounted filesystems only. Offline devices, disk serials and parity are not inventoried.'),
        '- Shares: ' . (!$active ? ($names === null ? 'unavailable; saved share directory unreadable.' : 'partial; saved share filenames only.')
            : 'partial; saved names and scoped runtime evidence where available. No recursive scan, ACLs or client/account lists.'),
        '- Docker, libvirt, network, and automation: unavailable in this pass; no services queried or started.', '',
        'Same-path candidates describe the source only. On Omarchy, verify filesystem identity, read-only rehearsal access, target paths and service-user permissions. A deferred share must not be replaced by empty data.', '',
        '## Storage', '',
    ], $notes ?: ['- No mounted storage evidence in scope.'], ['', '## Shares', ''], $shareNotes ?: ['- No share names collected.'],
        ['', '## Exclusions', ''], array_map(static fn(array $e): string => '- ' . $e['name'] . ': ' . $e['reason'], $exclusions) ?: ['- No additional exclusions recorded.'], ['']));
    return render($manifest, $report, $summary);
}

function render(array $manifest, string $report, string $summary): array
{
    foreach (['mounts', 'shares', 'exclusions', 'metadata'] as $key) {
        if (count($manifest[$key]) > LIMIT) throw new ExportError(SCOPE_ERROR);
    }
    $json = json_encode($manifest, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
    if (strlen($json) > JSON_LIMIT || strlen($report) > REPORT_LIMIT) throw new ExportError(SCOPE_ERROR);
    return ['json' => $json, 'markdown' => $report, 'summary' => $summary];
}

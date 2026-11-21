<?php
declare(strict_types=1);

use OmarchyExport\{ExportError, Probe};
use function OmarchyExport\{capture, render};

require_once __DIR__ . '/../src/host.php';

final class Fixture implements Probe
{
    public array $calls = [];
    public ?string $mode = 'STARTED';
    public ?string $end = null;
    public ?array $names = ['Media', 'Split', 'Offline', 'Unsupported', 'Nested', 'Symlink', 'Unverified', 'Case', 'case', 'PRIVATE<script>'];
    public ?string $mounts = <<<'ROWS'
25 1 0:1 / / rw - rootfs rootfs rw
26 25 0:2 net:[123] /run/netns/demo rw - nsfs nsfs rw
30 25 0:30 / /mnt/user rw - fuse.shfs shfs rw
32 25 0:32 / /mnt/tank rw - zfs tank/data rw
33 25 0:33 / /mnt/degraded ro - zfs bad/data ro
34 25 8:8 / /mnt/disk1 rw - xfs /dev/md1p1 rw
35 25 8:9 / /mnt/disks/USB\040Disk ro - exfat /dev/sdb1 ro
36 32 0:36 / /mnt/tank/Nested/Inner rw - zfs tank/data/Inner rw
ROWS;
    public ?string $poolsData = "tank\t18446744073709551615\tONLINE\nbad\t123\tDEGRADED\n";
    public ?string $blockData = '{"blockdevices":[{"path":"/dev/sdb1","maj:min":"8:9","fstype":"exfat","uuid":"12AB-CD34","serial":"PRIVATE_BLOCK"}]}';
    public function state(): ?string {
        $mode = in_array('state', $this->calls, true) ? ($this->end ?? $this->mode) : $this->mode;
        $this->calls[] = 'state';
        return $mode === null ? null : "mdState=\"$mode\"\nNAME=\"test-nas\"\nversion=\"7.3.4\"\ncsrf_token=\"PRIVATE_CSRF\"\n";
    }
    public function shareNames(): ?array { $this->calls[] = 'names'; return $this->names; }
    public function mountInfo(): ?string { $this->calls[] = 'mountinfo'; return $this->mounts === null ? null : $this->mounts . "\n"; }
    public function liveShares(): ?string {
        $this->calls[] = 'shares';
        return "[\"Media\"]\nexclusive=\"yes\"\nuseCache=\"only\"\ncachePool=\"tank\"\ncomment=\"PRIVATE_COMMENT\"\n"
            . "[Split]\nexclusive=\"no\"\n[Offline]\nexclusive=\"yes\"\n[Unsupported]\nexclusive=\"yes\"\n"
            . "[Nested]\nexclusive=\"yes\"\n[Symlink]\nexclusive=\"yes\"\n[LiveOnly]\nexclusive=\"no\"\n";
    }
    public function security(string $protocol): ?string {
        $this->calls[] = $protocol;
        return $protocol === 'smb' ? "[\"Media\"]\nexport=\"eh\"\nsecurity=\"private\"\nreadList=\"PRIVATE_SMB\"\n"
            : "[\"Media\"]\nexport=\"e\"\nsecurity=\"secure\"\nrule=\"PRIVATE_NFS\"\n";
    }
    public function pools(): ?string { $this->calls[] = 'pools'; return $this->poolsData; }
    public function blockDevices(): ?string { $this->calls[] = 'blocks'; return $this->blockData; }
    public function shareLink(string $name): ?string {
        $this->calls[] = "link:$name";
        return match ($name) {
            'Media', 'Nested', 'Symlink' => "/mnt/tank/$name",
            'Offline' => '/mnt/degraded/Offline',
            'Unsupported' => '/mnt/disk1/Unsupported',
            'Split' => '/mnt/tank/Split', // must not be considered without exclusive runtime state
            default => null,
        };
    }
    public array $branches = [];
    public function branchNames(string $root): ?array {
        return array_key_exists($root, $this->branches) ? $this->branches[$root] : [];
    }
    public function directory(string $path): ?array {
        $this->calls[] = "directory:$path";
        return $path === '/mnt/tank/Symlink' ? null : ['mode' => 0040750, 'uid' => 99, 'gid' => 100];
    }
}

function check(bool $ok, string $message): void
{
    if (!$ok) throw new RuntimeException($message);
}
function rejects(callable $fn, string $message): void
{
    try { $fn(); } catch (ExportError $error) {
        check(str_contains($error->getMessage(), $message), 'Unexpected failure: ' . $error->getMessage());
        return;
    }
    throw new RuntimeException('Expected failure: ' . $message);
}
function manifest(array $capture): array { return json_decode($capture['json'], true, 8, JSON_THROW_ON_ERROR); }

$quoted = \OmarchyExport\iniFields("[\"Media Share\"]\nexclusive=\"yes\"\n[Plain]\nexport=\"e\"\n", true);
check(($quoted['Media Share']['exclusive'] ?? null) === 'yes', 'quoted emhttp section name is decoded');
check(($quoted['Plain']['export'] ?? null) === 'e', 'plain section names still work');
check(\OmarchyExport\iniFields("[Media]\nexport=e\n[\"Media\"]\nexport=-\n", true) === [], 'duplicate decoded sections fail closed');

$f = new Fixture();
$active = capture($f);
$m = manifest($active);
$shares = array_column($m['shares'], null, 'name');
$mounts = array_column($m['mounts'], null, 'path');
check(count($mounts) === 2, 'expected two eligible mounts');
check($mounts['/mnt/tank']['poolGuid'] === '18446744073709551615', 'uint64 preserved');
check($mounts['/mnt/disks/USB Disk']['uuid'] === '12AB-CD34', 'exFAT identity and escaped mount path');
check($shares['Media']['path'] === '/mnt/tank/Media' && $shares['Media']['review'] === 'manual-review', 'exclusive source mapped');
foreach (['Split', 'Offline', 'Unsupported', 'Nested', 'Symlink', 'Unverified', 'LiveOnly'] as $deferred) {
    check($shares[$deferred]['review'] === 'deferred' && !isset($shares[$deferred]['path']), "defer $deferred");
}
check(!in_array('link:Split', $f->calls, true), 'no split share backing probe');
check(!in_array('directory:/mnt/tank/Nested', $f->calls, true), 'do not enter nested share');
check(!isset($shares['Case'], $shares['case']), 'case collision omitted');
check(str_contains($active['markdown'], 'SMB export eh, access private; NFS export e, access secure'), 'restricted settings reported');
check(str_contains($active['markdown'], '99:100, mode 0750'), 'source permissions reported');
check(str_contains($active['markdown'], 'pool health DEGRADED'), 'degraded pool reported');
check(!str_contains(implode('', $active), 'PRIVATE_') && !str_contains(implode('', $active), '<script>'), 'no raw secrets or markup');
check(manifest(capture(new Fixture())) === $m, 'stable IDs and deterministic manifest');

$f = new Fixture();
$selfBind = '45 25 0:1 /mnt /mnt rw shared:1 - rootfs rootfs rw';
$f->mounts = str_replace('30 25 ', "{$selfBind}\n30 25 ", $f->mounts);
$f->mounts = preg_replace('/^(30|32|33|34|35) 25 /m', '$1 45 ', $f->mounts);
check(manifest(capture($f)) === $m, 'root filesystem self-bind at /mnt preserves the inventory');
foreach ([
    str_replace('0:1', '0:77', $selfBind),
    str_replace('45 25 ', '45 26 ', $selfBind),
    str_replace(' /mnt /mnt ', ' /other /mnt ', $selfBind),
    str_replace('rootfs rootfs', 'tmpfs tmpfs', $selfBind),
    $selfBind . "\n46 45 0:77 / /mnt rw - tmpfs tmpfs rw",
] as $overmount) {
    $other = clone $f;
    $other->mounts = str_replace($selfBind, $overmount, $f->mounts);
    check(manifest(capture($other))['mounts'] === [], 'unexpected or stacked /mnt mount remains blocked');
}

$f = new Fixture();
$f->names[] = 'Models';
$f->mounts .= "\n46 32 0:46 / /mnt/tank/Models rw - zfs tank/data/Models rw"
    . "\n47 32 0:47 / /mnt/tank/Split rw - zfs tank/data/Split rw";
$f->branches = ['/mnt/tank' => ['Models', 'Split'], '/mnt/degraded' => ['Split']];
$result = capture($f);
$mapped = array_column(manifest($result)['shares'], null, 'name');
check(($mapped['Models']['path'] ?? null) === '/mnt/tank/Models', 'single observed ZFS dataset can be previewed without an exclusive alias');
check($mapped['Split']['review'] === 'deferred' && !isset($mapped['Split']['path']), 'split share is not selected');
check(str_contains($result['markdown'], '`/mnt/tank/Split`') && str_contains($result['markdown'], '`/mnt/degraded/Split`'), 'both split branches appear in report');
check(!isset($mapped['Nested']['path']), 'a deeper overmount still prevents share selection');
$incomplete = clone $f;
$incomplete->branches['/mnt/degraded'] = null;
check(!isset(array_column(manifest(capture($incomplete))['shares'], null, 'name')['Models']['path']), 'unreadable backing root prevents single-branch inference');
$bind = clone $f;
$bind->mounts = str_replace('46 32 0:46 / ', '46 32 0:46 /other ', $bind->mounts);
check(!isset(array_column(manifest(capture($bind))['shares'], null, 'name')['Models']['path']), 'a bind of a dataset subtree is not a dataset mount');

foreach (['STOPPED', 'STARTING', null] as $state) {
    $f = new Fixture();
    $f->mode = $state;
    $stopped = capture($f);
    check($f->calls === ['state', 'names'], 'inactive or unknown capture must only read state and names');
    $s = manifest($stopped);
    check($s['mounts'] === [] && count($s['shares']) > 0, 'inactive exports deferred names and no mounts');
    foreach ($s['shares'] as $row) check($row['review'] === 'deferred' && !isset($row['path'], $row['mount']), 'no inactive mapping');
}
$f = new Fixture(); $f->mode = 'STOPPED'; $stopped = capture($f, static fn() => throw new RuntimeException('Stopped capture must not probe inventory'));
$f = new Fixture(); $f->mounts = null; $f->names = null;
$unavailable = manifest(capture($f));
check($unavailable['mounts'] === [] && count($unavailable['exclusions']) === 2, 'unavailable evidence explicit');
check(!in_array('pools', $f->calls, true) && !in_array('blocks', $f->calls, true), 'no identity probes without mount evidence');
$f = new Fixture(); $f->poolsData = null; $f->blockData = null;
check(manifest(capture($f))['mounts'] === [], 'no identity guesses');
$f = new Fixture(); $f->mounts .= "\n99 25 0:98 / /mnt/tank rw - zfs shadow rw";
check(!isset(array_column(manifest(capture($f))['mounts'], null, 'path')['/mnt/tank']), 'stacking rejected');
$f = new Fixture(); $f->end = 'STOPPED';
rejects(fn() => capture($f), 'Source state changed');
$f = new Fixture(); $f->mode = 'STOPPED'; $f->names = array_map(fn($n) => "Share $n", range(0, 256));
rejects(fn() => capture($f), 'exceeds');
$large = $m;
$large['exclusions'] = array_map(fn($i) => ['name' => "Large $i", 'reason' => str_repeat('a', 400)], range(1, 160));
rejects(fn() => render($large, '', ''), 'exceeds');
rejects(fn() => render($m, str_repeat('a', \OmarchyExport\REPORT_LIMIT + 1), ''), 'exceeds');
check(\OmarchyExport\command(['/bin/printf', '%s', 'abcd'], 4) === 'abcd', 'command cap inclusive');
check(\OmarchyExport\command(['/bin/printf', '%s', 'abcd'], 3) === null, 'command output cap enforced');

echo json_encode(['active' => $active, 'dataset' => $result, 'stopped' => $stopped], JSON_THROW_ON_ERROR) . "\n";
fwrite(STDERR, "PHP exporter fixtures passed\n");

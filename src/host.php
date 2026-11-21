<?php
declare(strict_types=1);

namespace OmarchyExport;

require_once __DIR__ . '/collector.php';

function boundedRead(string $path, int $max): ?string
{
    if (is_link($path) || !is_file($path)) return null;
    $value = @file_get_contents($path, false, null, 0, $max + 1);
    return is_string($value) && strlen($value) <= $max ? $value : null;
}

// All callers supply fixed commands; proc_open's array form never invokes a shell.
// The outer timeout owns the process group for WebGUI captures and documented CLI runs.
function command(array $argv, int $max, array $allowedExit = [0]): ?string
{
    $spec = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']];
    $process = @proc_open($argv, $spec, $pipes, '/', ['LC_ALL' => 'C', 'PATH' => '/usr/sbin:/usr/bin:/sbin:/bin']);
    if (!is_resource($process)) return null;
    try {
        $value = stream_get_contents($pipes[1], $max + 1);
    } finally {
        fclose($pipes[1]);
        $exit = proc_close($process);
    }
    return in_array($exit, $allowedExit, true) && is_string($value) && strlen($value) <= $max ? $value : null;
}

final class HostProbe implements Probe
{
    public function state(): ?string { return boundedRead('/var/local/emhttp/var.ini', 128 * 1024); }
    public function mountInfo(): ?string { return boundedRead('/proc/self/mountinfo', 1024 * 1024); }
    public function liveShares(): ?string { return boundedRead('/var/local/emhttp/shares.ini', 512 * 1024); }
    public function security(string $protocol): ?string
    {
        return match ($protocol) {
            'smb' => boundedRead('/var/local/emhttp/sec.ini', 256 * 1024),
            'nfs' => boundedRead('/var/local/emhttp/sec_nfs.ini', 256 * 1024),
            default => null,
        };
    }

    public function shareNames(): ?array
    {
        $dir = '/boot/config/shares';
        if (is_link($dir) || !is_dir($dir)) return null;
        $handle = @opendir($dir);
        if ($handle === false) return null;
        $names = [];
        $entries = 0;
        try {
            while (($file = readdir($handle)) !== false) {
                if (++$entries > 1024) throw new ExportError(SCOPE_ERROR);
                if (!str_ends_with($file, '.cfg')) continue;
                $path = "$dir/$file";
                if (!is_link($path) && is_file($path)) $names[] = substr($file, 0, -4);
                if (count($names) > LIMIT) throw new ExportError(SCOPE_ERROR);
            }
        } finally {
            closedir($handle);
        }
        return $names;
    }

    public function pools(): ?string
    {
        // -H machine output, -p exact integers; imported pools only.
        $bin = is_executable('/usr/sbin/zpool') ? '/usr/sbin/zpool' : '/sbin/zpool';
        return command(['/usr/bin/timeout', '--foreground', '-k', '1s', '3s', $bin,
            'list', '-H', '-p', '-o', 'name,guid,health'], 64 * 1024);
    }

    public function blockDevices(): ?string
    {
        $bin = is_executable('/usr/bin/lsblk') ? '/usr/bin/lsblk' : '/bin/lsblk';
        return command(['/usr/bin/timeout', '--foreground', '-k', '1s', '3s', $bin,
            '--list', '--json', '--properties-by', 'udev', '--output', 'PATH,MAJ:MIN,FSTYPE,UUID'], 128 * 1024);
    }

    public function shareLink(string $name): ?string
    {
        if (!nameOk($name)) return null;
        $link = @readlink('/mnt/user/' . $name);
        return is_string($link) ? $link : null;
    }

    public function directory(string $path): ?array
    {
        if (!pathOk($path)) return null;
        clearstatcache(true);
        if (@realpath($path) !== $path) return null;
        $st = @lstat($path);
        return is_array($st) && ($st['mode'] & 0170000) === 0040000 ? $st : null;
    }
}

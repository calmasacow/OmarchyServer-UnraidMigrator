<?php
declare(strict_types=1);

namespace OmarchyExport;

// Only selected fields leave this module; raw CLI responses and domain XML never do.
function ivText(mixed $v, string $pattern = '~\A[A-Za-z0-9_./:+@ %-]{1,512}\z~D'): ?string
{
    return is_string($v) && preg_match($pattern, $v) === 1 ? $v : null;
}

function ivPath(mixed $v): ?string
{
    return is_string($v) && str_starts_with($v, '/') ? ivText($v) : null;
}

function ivId(mixed $v): ?string
{
    return ivText($v, '~\A[A-Za-z0-9_.:+-]{1,128}\z~D');
}

function ivAddress(mixed $v): ?string
{
    if (!is_string($v)) return null;
    $p = explode('/', $v, 2);
    if (filter_var($p[0], FILTER_VALIDATE_IP) === false) return null;
    $limit = str_contains($p[0], ':') ? 128 : 32;
    return !isset($p[1]) || (preg_match('/\A[0-9]{1,3}\z/D', $p[1]) === 1 && (int)$p[1] <= $limit) ? $v : null;
}

function ivSet(array $data): array
{
    return array_filter($data, static fn($v) => $v !== null && $v !== [] && $v !== '');
}

function ivRows(mixed $data): array
{
    return is_array($data) ? array_filter($data, 'is_array') : [];
}

function ivJson(?string $data): ?array
{
    $v = json_decode($data ?? '', true, 64);
    return is_array($v) && array_is_list($v) ? $v : null;
}

function ivNumber(mixed $v): ?int
{
    return is_int($v) && $v >= 0 ? $v : null;
}

function ivStatus(string $status, array $rows = [], ?string $note = null): array
{
    return ivSet(['status' => $status, 'count' => count($rows), 'note' => $note, 'items' => $rows]);
}

function dockerRecord(array $v): ?array
{
    $name = ivId(ltrim((string)($v['Name'] ?? ''), '/'));
    if ($name === null) return null;
    $c = $v['Config'] ?? [];
    $h = $v['HostConfig'] ?? [];
    $n = $v['NetworkSettings'] ?? [];
    $mounts = $ports = $networks = $devices = $deviceRequests = [];
    foreach (ivRows($v['Mounts'] ?? null) as $m) {
        if (!in_array($m['Type'] ?? null, ['bind','volume','tmpfs'], true)) continue;
        $mounts[] = ivSet(['type' => $m['Type'], 'name' => ivId($m['Name'] ?? null), 'source' => ivPath($m['Source'] ?? null),
            'target' => ivPath($m['Destination'] ?? null), 'rw' => is_bool($m['RW'] ?? null) ? $m['RW'] : null,
            'propagation' => ivId($m['Propagation'] ?? null)]);
    }
    foreach (($h['PortBindings'] ?? []) ?: [] as $port => $bindings) {
        if (!preg_match('~\A[0-9]{1,5}/(?:tcp|udp|sctp)\z~D', (string)$port)) continue;
        foreach (ivRows($bindings) as $b) $ports[] = ivSet(['container' => $port, 'hostIp' => ivAddress($b['HostIp'] ?? null),
            'hostPort' => ivText($b['HostPort'] ?? null, '~\A[0-9]{1,5}\z~D')]);
    }
    foreach (ivRows($n['Networks'] ?? null) as $key => $a) {
        if (($net = ivId((string)$key)) === null) continue;
        $networks[] = ivSet(['network' => $net, 'ipv4' => ivAddress($a['IPAddress'] ?? null), 'ipv6' => ivAddress($a['GlobalIPv6Address'] ?? null),
            'requestedIpv4' => ivAddress($a['IPAMConfig']['IPv4Address'] ?? null), 'requestedIpv6' => ivAddress($a['IPAMConfig']['IPv6Address'] ?? null)]);
    }
    foreach (ivRows($h['Devices'] ?? null) as $d) $devices[] = ivSet(['host' => ivPath($d['PathOnHost'] ?? null),
        'guest' => ivPath($d['PathInContainer'] ?? null), 'mode' => ivText($d['CgroupPermissions'] ?? null, '~\A[rwm]{1,3}\z~D')]);
    foreach (ivRows($h['DeviceRequests'] ?? null) as $d) $deviceRequests[] = ivSet(['driver' => ivId($d['Driver'] ?? null),
        'count' => is_int($d['Count'] ?? null) ? $d['Count'] : null,
        'capabilities' => array_values(array_filter(array_map('OmarchyExport\\ivId', is_array($d['Capabilities'][0] ?? null) ? $d['Capabilities'][0] : [])))]);
    $image = ivText($c['Image'] ?? null, '~\A(?:[A-Za-z0-9_.:-]+/)*[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?(?:@sha256:[a-f0-9]{64})?\z~D');
    return ivSet(['name' => $name, 'image' => $image, 'imageId' => ivText($v['Image'] ?? null, '~\Asha256:[a-f0-9]{64}\z~D'),
        'state' => ivId($v['State']['Status'] ?? null), 'user' => ivId($c['User'] ?? null),
        'management' => isset($c['Labels']['com.docker.compose.project']) ? 'Compose' : 'not verified',
        'composeProject' => ivId($c['Labels']['com.docker.compose.project'] ?? null),
        'composeService' => ivId($c['Labels']['com.docker.compose.service'] ?? null),
        'restart' => ivId($h['RestartPolicy']['Name'] ?? null), 'restartRetries' => ivNumber($h['RestartPolicy']['MaximumRetryCount'] ?? null),
        'privileged' => is_bool($h['Privileged'] ?? null) ? $h['Privileged'] : null,
        'capAdd' => array_values(array_filter(array_map('OmarchyExport\\ivId', is_array($h['CapAdd'] ?? null) ? $h['CapAdd'] : []))),
        'capDrop' => array_values(array_filter(array_map('OmarchyExport\\ivId', is_array($h['CapDrop'] ?? null) ? $h['CapDrop'] : []))),
        'networkMode' => ivId($h['NetworkMode'] ?? null), 'mounts' => $mounts, 'publishedPorts' => $ports, 'networks' => $networks,
        'devices' => $devices, 'deviceRequests' => $deviceRequests, 'commandConfigured' => !empty($c['Cmd']),
        'entrypointConfigured' => !empty($c['Entrypoint']), 'environmentConfigured' => !empty($c['Env'])]);
}

function dockerNetworkRecord(array $v): ?array
{
    if (($name = ivId($v['Name'] ?? null)) === null) return null;
    $ipam = [];
    foreach (ivRows($v['IPAM']['Config'] ?? null) as $a) $ipam[] = ivSet(['subnet' => ivAddress($a['Subnet'] ?? null),
        'gateway' => ivAddress($a['Gateway'] ?? null), 'range' => ivAddress($a['IPRange'] ?? null)]);
    return ivSet(['name'=>$name, 'driver'=>ivId($v['Driver'] ?? null), 'scope'=>ivId($v['Scope'] ?? null),
        'parent'=>ivId($v['Options']['parent'] ?? null), 'ipam'=>$ipam,
        'internal'=>is_bool($v['Internal'] ?? null) ? $v['Internal'] : null]);
}

function vmRecord(string $xml, string $uuid, ?array $active): ?array
{
    if (!function_exists('simplexml_load_string') || stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) return null;
    $v = @simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
    if ($v === false || $v->getName() !== 'domain' || (string)$v->uuid !== $uuid) return null;
    $disks = $interfaces = $boot = $hostdev = [];
    foreach ($v->devices->disk ?? [] as $d) {
        $chain = [];
        for ($x = $d->backingStore ?? null, $i = 0; $x !== null && count($x) && $i < 16; $x = $x->backingStore ?? null, ++$i) {
            $chain[] = ivSet(['source'=>ivPath((string)($x->source['file'] ?? $x->source['dev'] ?? '')), 'format'=>ivId((string)($x->format['type'] ?? ''))]);
        }
        $disks[] = ivSet(['device'=>ivId((string)$d['device']), 'type'=>ivId((string)$d['type']),
            'format'=>ivId((string)($d->driver['type'] ?? '')), 'source'=>ivPath((string)($d->source['file'] ?? $d->source['dev'] ?? $d->source['dir'] ?? '')),
            'target'=>ivId((string)($d->target['dev'] ?? '')), 'bus'=>ivId((string)($d->target['bus'] ?? '')), 'readonly'=>isset($d->readonly),
            'bootOrder'=>ivId((string)($d->boot['order'] ?? '')), 'declaredBackingChain'=>$chain]);
    }
    foreach ($v->devices->interface ?? [] as $n) $interfaces[] = ivSet(['type'=>ivId((string)$n['type']),
        'source'=>ivId((string)($n->source['bridge'] ?? $n->source['network'] ?? $n->source['dev'] ?? '')),
        'mac'=>ivText((string)($n->mac['address'] ?? ''), '~\A(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\z~D'),
        'model'=>ivId((string)($n->model['type'] ?? ''))]);
    foreach ($v->os->boot ?? [] as $b) if (($x = ivId((string)$b['dev'])) !== null) $boot[] = $x;
    foreach ($v->devices->hostdev ?? [] as $h) {
        $a = $h->source->address ?? null;
        $parts = [];
        foreach (['domain','bus','slot','function','device'] as $k) if (($x = ivId((string)($a[$k] ?? ''))) !== null) $parts[$k] = $x;
        $hostdev[] = ivSet(['type'=>ivId((string)$h['type']), 'address'=>$parts,
            'vendor'=>ivId((string)($h->source->vendor['id'] ?? '')), 'product'=>ivId((string)($h->source->product['id'] ?? ''))]);
    }
    return ivSet(['name'=>ivText((string)$v->name), 'uuid'=>$uuid, 'persistent'=>true, 'active'=>$active === null ? null : isset($active[$uuid]),
        'vcpus'=>ivId((string)$v->vcpu), 'memory'=>ivId((string)$v->memory), 'memoryUnit'=>ivId((string)($v->memory['unit'] ?? '')),
        'machine'=>ivId((string)($v->os->type['machine'] ?? '')), 'firmware'=>ivId((string)($v->os['firmware'] ?? '')),
        'loader'=>ivPath((string)($v->os->loader ?? '')), 'nvram'=>ivPath((string)($v->os->nvram ?? '')),
        'tpm'=>isset($v->devices->tpm), 'boot'=>$boot, 'disks'=>$disks, 'interfaces'=>$interfaces, 'passthrough'=>$hostdev]);
}

function hostNetworkRecords(array $links, array $addresses, array $routes): array
{
    $byName = [];
    foreach (ivRows($links) as $link) {
        if (($name = ivId($link['ifname'] ?? null)) === null) continue;
        $data = $link['linkinfo']['info_data'] ?? [];
        $byName[$name] = ivSet(['name'=>$name, 'index'=>ivNumber($link['ifindex'] ?? null), 'kind'=>ivId($link['linkinfo']['info_kind'] ?? $link['link_type'] ?? null),
            'state'=>ivId($link['operstate'] ?? null), 'mtu'=>ivNumber($link['mtu'] ?? null), 'master'=>ivId($link['master'] ?? null),
            'parent'=>ivId($link['link'] ?? null), 'parentIndex'=>ivNumber($link['link_index'] ?? null),
            'vlan'=>ivNumber($data['id'] ?? null), 'bondMode'=>ivId($data['mode'] ?? null)]);
    }
    foreach (ivRows($addresses) as $row) {
        $name = ivId($row['ifname'] ?? null);
        if ($name === null || !isset($byName[$name])) continue;
        foreach (ivRows($row['addr_info'] ?? null) as $a) {
            if (is_int($a['prefixlen'] ?? null) && ($ip = ivAddress((string)($a['local'] ?? '') . '/' . $a['prefixlen'])) !== null) {
                $byName[$name]['addresses'][] = ivSet(['address'=>$ip, 'scope'=>ivId($a['scope'] ?? null)]);
            }
        }
    }
    $out = [];
    foreach (ivRows($routes) as $route) {
        $dst = ($route['dst'] ?? '') === 'default' ? 'default' : ivAddress($route['dst'] ?? null);
        if ($dst === null) continue;
        $out[] = ivSet(['destination'=>$dst, 'via'=>ivAddress($route['gateway'] ?? null), 'interface'=>ivId($route['dev'] ?? null),
            'source'=>ivAddress($route['prefsrc'] ?? null), 'protocol'=>ivId($route['protocol'] ?? null), 'metric'=>ivNumber($route['metric'] ?? null),
            'table'=>ivId($route['table'] ?? null) ?? ivNumber($route['table'] ?? null)]);
    }
    return ['interfaces'=>array_values($byName), 'routes'=>$out];
}

function ivIds(?string $raw, string $pattern): ?array
{
    if ($raw === null) return null;
    $ids = preg_split('/\s+/', trim($raw), -1, PREG_SPLIT_NO_EMPTY);
    if (count($ids) > LIMIT) return null;
    foreach ($ids as $id) if (preg_match($pattern, $id) !== 1) return null;
    return array_values(array_unique($ids));
}

// Already-running daemons only. Fixed local Unix sockets; no remote contexts or service calls.
function ivRunning(string $daemon, string $socket): bool
{
    clearstatcache(true, $socket);
    return @filetype($socket) === 'socket'
        && command(['/usr/bin/timeout','1s','/bin/pidof',$daemon], 4096) !== null;
}

function ivCmd(array $argv, int $cap = 1048576): ?string
{
    return command(['/usr/bin/timeout','--foreground','-k','1s','2s',...$argv], $cap);
}

function hostInventory(): array
{
    $dockerSock = '/var/run/docker.sock';
    $libvirtSock = '/var/run/libvirt/libvirt-sock-ro';
    $docker = ['/usr/bin/docker','--host','unix://' . $dockerSock];
    $virsh = ['/usr/bin/virsh','--readonly','--connect','qemu+unix:///system?socket=' . $libvirtSock];
    $dockerSections = [];
    foreach (['Docker containers' => ['container','ps','--all','--quiet','--no-trunc'], 'Docker networks' => ['network','ls','--quiet','--no-trunc']] as $title => $list) {
        if (!ivRunning('dockerd', $dockerSock)) { $dockerSections[$title] = ivStatus('unavailable', [], 'Local Docker daemon not running or socket missing.'); continue; }
        $ids = ivIds(ivCmd([...$docker,...$list], 65536), '~\A[a-f0-9]{12,64}\z~D');
        if ($ids === null) { $dockerSections[$title] = ivStatus('unavailable', [], 'Listing failed or exceeded capture bounds.'); continue; }
        $rows = [];
        foreach (array_chunk($ids, 12) as $batch) {
            if (!ivRunning('dockerd', $dockerSock)) break;
            $items = ivJson(ivCmd([...$docker,$list[0],'inspect',...$batch], 4194304));
            foreach (ivRows($items) as $v) {
                $record = $list[0] === 'container' ? dockerRecord($v) : dockerNetworkRecord($v);
                if ($record !== null) $rows[] = $record;
            }
        }
        $dockerSections[$title] = ivStatus(count($ids) === count($rows) ? 'observed' : 'partial', $rows,
            'Live daemon snapshot; environment values, commands, arbitrary labels, secrets and raw settings omitted.');
    }
    $vm = ivStatus('unavailable', [], 'Local monolithic libvirt daemon or read-only socket not running.');
    if (ivRunning('libvirtd', $libvirtSock)) {
        $pattern = '~\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z~D';
        $ids = ivIds(ivCmd([...$virsh,'list','--all','--persistent','--uuid'],65536), $pattern);
        $live = ivIds(ivCmd([...$virsh,'list','--uuid'],65536), $pattern);
        $active = $live === null ? null : array_fill_keys($live,true);
        $rows = [];
        foreach ($ids ?? [] as $id) {
            if (!ivRunning('libvirtd', $libvirtSock)) break;
            $xml = ivCmd([...$virsh,'dumpxml','--inactive',$id],262144);
            if ($xml !== null && ($v = vmRecord($xml,$id,$active)) !== null) $rows[] = $v;
        }
        $vm = ivStatus($ids === null ? 'unavailable' : (count($ids) === count($rows) && $active !== null ? 'observed' : 'partial'), $rows,
            'Persistent domain settings only. Backing chains are declarations, not disk probes; guest contents and raw XML omitted.');
    }
    $ip = '/usr/sbin/ip';
    $links = ivJson(ivCmd([$ip,'-j','-d','link','show']));
    $addresses = ivJson(ivCmd([$ip,'-j','addr','show']));
    $v4 = ivJson(ivCmd([$ip,'-j','-4','route','show','table','all']));
    $v6 = ivJson(ivCmd([$ip,'-j','-6','route','show','table','all']));
    $net = hostNetworkRecords($links ?? [], $addresses ?? [], array_merge($v4 ?? [],$v6 ?? []));
    $dns = [];
    if (($resolv = @realpath('/etc/resolv.conf')) !== false && ($raw = boundedRead($resolv, 16384)) !== null) {
        foreach (preg_split('/\R/', $raw) as $line) if (preg_match('/^nameserver\s+(\S+)/', $line, $m) && ($ip = ivAddress($m[1])) !== null) $dns[] = $ip;
    }
    return $dockerSections + ['Libvirt virtual machines'=>$vm, 'Host network'=>ivSet(['status'=>in_array(null,[$links,$addresses,$v4,$v6],true) ? 'partial' : 'observed',
        ...$net, 'dns'=>array_values(array_unique($dns)), 'note'=>'Runtime topology; DHCP reservations, firewall/ingress policies and automation are not inferred.'])];
}

function inventoryMarkdown(array $inventory): array
{
    $lines = [];
    foreach ($inventory as $name => $value) {
        $lines[] = '## ' . $name;
        $lines[] = '';
        // Render only projected fields. Every item stays on one line and the report
        // has a global size cap; no input can supply a Markdown fence line.
        $lines[] = '```json';
        $encode = static fn($v): string => json_encode($v, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
        $fields = [];
        foreach ($value as $key => $field) {
            $body = is_array($field) && array_is_list($field) && $field !== []
                ? "[\n    " . implode(",\n    ", array_map($encode, $field)) . "\n  ]" : $encode($field);
            $fields[] = '  ' . $encode($key) . ': ' . $body;
        }
        $lines[] = "{\n" . implode(",\n", $fields) . "\n}";
        $lines[] = '```';
        $lines[] = '';
    }
    return $lines;
}

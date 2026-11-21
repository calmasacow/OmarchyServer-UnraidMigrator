<?php
declare(strict_types=1);
require_once __DIR__ . '/../src/host.php';
use function OmarchyExport\{dockerRecord,dockerNetworkRecord,vmRecord,hostNetworkRecords,inventoryMarkdown};
function verify(bool $pass, string $reason): void { if (!$pass) throw new RuntimeException($reason); }
$d = dockerRecord(['Name'=>'/example', 'Image'=>'sha256:'.str_repeat('a',64), 'Config'=>['Image'=>'repo/test:latest', 'Env'=>['PASSWORD=SECRET_FIXTURE'], 'Cmd'=>['SECRET_FIXTURE'], 'Labels'=>['com.docker.compose.project'=>'project','arbitrary'=>'SECRET_FIXTURE']], 'Mounts'=>[['Type'=>'bind','Source'=>'/srv/data','Destination'=>'/data','RW'=>false]], 'HostConfig'=>['PortBindings'=>['80/tcp'=>[['HostIp'=>'127.0.0.1','HostPort'=>'8080']]], 'Privileged'=>false], 'NetworkSettings'=>['Networks'=>['br0'=>['IPAMConfig'=>['IPv4Address'=>'192.0.2.10']]]]]);
verify(($d['mounts'][0]['rw'] ?? null) === false && $d['publishedPorts'][0]['hostPort'] === '8080', 'Docker bind mode and port');
verify($d['networks'][0]['requestedIpv4'] === '192.0.2.10' && $d['composeProject'] === 'project', 'Docker network and management');
$n = dockerNetworkRecord(['Name'=>'br0','IPAM'=>['Config'=>[['Subnet'=>'192.0.2.0/24','Gateway'=>'192.0.2.1']]],'Options'=>['parent'=>'bond0','SECRET_FIXTURE'=>'SECRET_FIXTURE']]);
verify($n['ipam'][0]['gateway'] === '192.0.2.1', 'Docker subnet');
$h = hostNetworkRecords([['ifname'=>'br0','linkinfo'=>['info_kind'=>'bridge'],'mtu'=>1500]], [['ifname'=>'br0','addr_info'=>[['local'=>'192.0.2.2','prefixlen'=>24]]]], [['dst'=>'default','dev'=>'br0','gateway'=>'192.0.2.1']]);
verify($h['interfaces'][0]['addresses'][0]['address'] === '192.0.2.2/24' && $h['routes'][0]['via'] === '192.0.2.1', 'network topology');
$uuid = '12345678-1234-1234-1234-123456789abc';
$xml = '<domain><name>demo</name><uuid>'.$uuid.'</uuid><vcpu>4</vcpu><memory unit="KiB">4096</memory><devices><disk device="disk" type="file"><driver type="qcow2"/><source file="/vm/demo.img"/><target dev="vda" bus="virtio"/><backingStore><format type="raw"/><source file="/vm/base.img"/></backingStore></disk><interface type="bridge"><source bridge="br0"/><mac address="52:54:00:00:00:10"/></interface><graphics passwd="SECRET_FIXTURE"/></devices></domain>';
$v = null;
if (function_exists('simplexml_load_string')) {
    $v = vmRecord($xml,$uuid,[$uuid=>true]);
    verify($v['active'] && $v['disks'][0]['declaredBackingChain'][0]['source'] === '/vm/base.img' && $v['interfaces'][0]['source'] === 'br0', 'libvirt disk and NIC');
    verify(vmRecord('<!DOCTYPE domain>'.$xml,$uuid,null) === null, 'DTD rejected');
} else {
    verify(vmRecord($xml,$uuid,null) === null, 'missing SimpleXML handled');
}
$markdown = implode("\n", inventoryMarkdown(['Docker'=>['items'=>[$d,$n]],'VM'=>['items'=>[$v]],'Network'=>$h]));
verify(!str_contains($markdown,'SECRET_FIXTURE'), 'raw secrets omitted');
preg_match_all('/^```json\n(.*?)\n```$/ms', $markdown,$matches);
verify(count($matches[1]) === 3, 'Markdown fenced sections');
foreach ($matches[1] as $json) json_decode($json,true,32,JSON_THROW_ON_ERROR);
echo "Inventory projection fixtures passed\n";

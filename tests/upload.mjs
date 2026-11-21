import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {resolve} from 'node:path'
import {pathToFileURL} from 'node:url'

assert.ok(process.argv[2], 'Pass the path to the Omarchy Server checkout with local preview support.')
const {previewUploadedLocalUnraid} = await import(pathToFileURL(resolve(process.argv[2], 'omarchyd/unraid-local.mjs')).href)

const captures = JSON.parse(await readFile('/dev/stdin', 'utf8'))
for (const [name, capture] of Object.entries(captures)) {
  assert.ok(Buffer.byteLength(capture.json) <= 60 * 1024)
  const manifest = JSON.parse(capture.json)
  assert.ok(manifest.metadata.every(m => Object.hasOwn(m, 'deferReason') && !Object.hasOwn(m, 'path')))
  const targetProbe = {
    mountTable: async () => manifest.mounts.map(m => ({target: m.path, root: '/', fsType: m.fsType,
      source: m.dataset ?? '/dev/test', readOnly: true})),
    realpath: async path => path,
    isDirectory: async () => true,
    poolGuid: async () => '18446744073709551615',
    uuid: async () => '12AB-CD34',
  }
  const {status, plan} = await previewUploadedLocalUnraid(manifest, {probe: targetProbe})
  assert.equal(status, 'preview')
  assert.equal(plan.requireReadOnly, true)
  assert.ok(plan.metadata.every(m => m.status === 'deferred'))
  if (name === 'active') {
    assert.equal(plan.mounts.length, 2)
    assert.ok(plan.mounts.every(m => m.status === 'verified'))
    assert.equal(plan.blocked, false)
    assert.equal(plan.shares.find(s => s.name === 'Media').status, 'manual-review')
    assert.equal(plan.shares.find(s => s.name === 'Split').status, 'deferred')
    const writable = {...targetProbe, mountTable: async () => (await targetProbe.mountTable()).map(m => ({...m, readOnly: false}))}
    const blocked = (await previewUploadedLocalUnraid(manifest, {probe: writable})).plan
    assert.equal(blocked.blocked, true)
    assert.ok(blocked.shares.find(s => s.name === 'Media').issues.includes('backing-mount-is-writable'))
  } else {
    assert.equal(name, 'stopped')
    assert.equal(plan.mounts.length, 0)
    assert.ok(plan.shares.length > 0 && plan.shares.every(s => s.status === 'deferred'))
  }
}
assert.deepEqual(Object.keys(captures).sort(), ['active', 'stopped'])
console.log('Actual previewUploadedLocalUnraid accepted both PHP fixtures; writable rehearsal blocked')

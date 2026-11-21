# Omarchy Migration Export for Unraid

First pass targeting Unraid **7.3.4**. Produces `unraid-migration-report.md` for private review and `unraid-migration-manifest.json` for Omarchy Settings → Move from Unraid. JSON v1 is preview-only; acceptance does not mean the data is ready. Review exclusions, confirm target mounts are read-only during rehearsal, and check access under the eventual service accounts. Never substitute an empty directory for a deferred share.

## WebGUI pilot install

This is a pre-release. The collector was smoke-tested on Unraid 7.3.4 with the array stopped; WebGUI installation, authentication, downloads and live-array collection still need a pilot test. The plugin itself does not start or stop the array. Only install on a system where you are authorised to test it.

1. Open **Plugins → Install Plugin** in Unraid, leave **Force Install** unchecked, and paste the [versioned `.plg` URL](https://github.com/calmasacow/OmarchyServer-UnraidMigrator/releases/download/v2026.11.21/omarchy-migration-export.plg).
2. Open **Tools → Omarchy Migration Export**, click **Generate**, and download both files. A running array allows eligible live storage mappings; a stopped array gives a partial configuration-only report. Neither collects workloads in this version.
3. To remove the pilot, use **Plugins → Installed Plugins → Remove**.

## What it collects

- **Stopped, transitional or unknown array state:** only allowlisted identity/state from emhttp `var.ini` and regular, non-symlink `.cfg` filenames under `/boot/config/shares`. No `.cfg` file bodies, `/mnt` inspection, identity tools, or service calls. Saved names are not proof that a share is present or mounted.
- **Started array:** a bounded read of mountinfo and emhttp share/security snapshots. Candidates are single, visible filesystem roots directly under `/mnt` or `/mnt/disks`; only ONLINE ZFS with verified pool GUID or kernel exFAT with unique UUID and matching udev-derived `lsblk` device identity. Missing tools, unsupported `lsblk` options, degraded pools, aliases, stacked/nested mounts and unsupported filesystem types are not guessed. A share is mapped only when emhttp reports it exclusive and the actual `/mnt/user/<name>` symlink points directly at a canonical directory on an eligible mount, with no intervening or nested mount at that share. Otherwise it is deferred (including possibly split or unavailable shares). Nested share datasets and non-exclusive shares are deliberately deferred even when they might in fact be single-root.
- The report includes bounded settings for SMB/NFS and storage policy plus numeric source ownership/mode where verified. No rule/account lists, ACLs, raw configs, network or workload collection, or disk serials/offline device inventory. Docker and libvirt are never contacted. Artifacts still contain private names, paths and storage identifiers.
- Each v1 list is capped at 256, the manifest at 60 KiB (including its final newline), and Markdown at 256 KiB. Oversize exports fail rather than truncating. The UI takes no scope parameters; use a smaller separately reviewed offline manifest if the source does not fit. A capture is not atomic: avoid running it during a storage change. The exporter rejects observed changes to active state, mountinfo or share topology before returning.

## Local verification and packaging

From `unraid-exporter/`, with PHP 8.3+ and Node available on the development workstation:

```bash
set -o pipefail
for f in src/*.php tests/*.php build-plg.php; do php -n -l "$f" || exit; done
# Set OMARCHY_SERVER_CHECKOUT to a checkout with local preview support.
php -n tests/fixtures.php | node tests/upload.mjs "${OMARCHY_SERVER_CHECKOUT:?Set the Omarchy Server checkout path}"
mkdir -p dist
php -n build-plg.php > dist/omarchy-migration-export.plg
php tests/package.php dist/omarchy-migration-export.plg
sha256sum dist/omarchy-migration-export.plg
```

`tests/upload.mjs` imports the actual `previewUploadedLocalUnraid` handler from the adjacent Omarchy checkout, using synthetic target probes. `tests/package.php` requires PHP DOM; the collector and package builder do not. PHP fixtures alone can run from staged source on Unraid with `php -n tests/fixtures.php >/dev/null`; they never inspect that machine's storage or services. No Python or Node is needed on Unraid.

## Operator-only staging and rollback

**WebGUI authorization, boot registration, and install/removal are not verified on 7.3.4.** Do a disposable Unraid test before a real source capture. The single `.plg` embeds five files, has no download/update URL, and adds no listener, service, schedule or persistent export directory. Native installation will persist the plugin definition on boot flash; generated inventory is never saved by the plugin.

1. Check the `.plg` checksum on both sides. Stage it as `/tmp/omarchy-migration-export.plg` using an approved operator transfer. Check that neither `/usr/local/emhttp/plugins/omarchy-migration-export` nor `/usr/local/libexec/omarchy-migration-export` already belongs to anything. From the Unraid local console, deliberately install the local file with `plugin install /tmp/omarchy-migration-export.plg`. Do not expose the WebGUI or weaken its session/CSRF protections to make this test work.
2. With the array **stopped**, record array state, mount table and Docker/libvirt process presence before testing. In a signed-out/private window check that Tools and the capture route cannot return inventory, including on POST. In an authenticated session check GET cannot collect, and an authenticated POST without a valid stock WebGUI CSRF token is rejected. The endpoint relies on the native WebGUI prepend CSRF check and also checks for the native login session before invoking PHP CLI. If the platform does not provide those mechanisms as expected, stop and use CLI only.
3. As admin use Tools → Omarchy Migration Export → Generate. Confirm both downloads work from that one capture, no inventory is served as a static file, the response is `Cache-Control: no-store, private`, and the Markdown and JSON contain deferred saved names with no mounts. Verify the before/after array state, mounts and Docker/libvirt presence match and no inventory was created on flash or a share. Do not start the array for this check. Close the tab and handle downloaded files as private.
4. Remove via Plugins → Installed Plugins → Remove (or `plugin remove omarchy-migration-export.plg`). Verify the two plugin directories and Tools item are gone; if install failed midway, inspect only the two owned paths and the registered plugin definition before manual cleanup. Remove the staged `.plg` from `/tmp` separately. A failure of this gate is not grounds to test on a production host.

CLI fallback without installing: stage the three PHP files `collector.php`, `host.php`, and `export.php` together in a private local directory, then from that directory run:

```bash
/usr/bin/timeout -k 1s 15s /usr/bin/php -n -d display_errors=0 -d memory_limit=64M ./export.php bundle
```

`bundle` writes one JSON envelope to stdout (`json`, `markdown`, `summary`), not the upload file itself. To obtain just one artifact use `json` or `markdown` instead; running these separately takes separate captures. Exit `2` means invalid CLI usage, `3` means the collector refused the capture, and a timeout/nonzero unexpected exit is not a valid artifact. Capture to a private workstation location if redirecting stdout; do not persist reports on the boot flash or shares.

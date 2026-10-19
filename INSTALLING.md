# Installing Svavyom

**Svavyom is a Development Preview / Pre-Alpha.** One host, **Ubuntu 24.04 LTS, x86_64, KVM, libvirt `qemu:///system`**. Use it to evaluate and for non-critical work; read [`KNOWN-LIMITATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/KNOWN-LIMITATIONS.md) first. The installer is `svavyom-ctl`; **every command that changes the host prints its plan and changes nothing until you add `--apply`.**

## 1. Get the release and check it
From the project's releases page download the archive `svavyom-<version>.tar.gz` and its `SHA256SUMS`. The release is **not signed yet**, so verify it against checksums obtained over a channel you trust (the release page and, ideally, a second source):
```
tar xzf svavyom-<version>.tar.gz && cd svavyom-<version>
sha256sum -c SHA256SUMS                               # every file, nothing unlisted
bin/svavyom-ctl verify-artifact .                     # the same, plus no symlink, no unexpected file
```
Or build it yourself from the source (`BUILDING.md`).

## 2. Prepare the host
```
sudo apt install qemu-system-x86 libvirt-daemon-system libvirt-clients
sudo systemctl enable --now libvirtd
bin/svavyom-ctl preflight            # read-only: PASS / FAIL / NOT_READY with typed findings (OPERATIONS.md in the documentation repository)
```
You need: hardware virtualization enabled (VT-x/AMD-V; `/dev/kvm` present), AppArmor enabled, at least 30 GiB free under `/var/lib`, and a user with `sudo`. A libvirt storage pool and the `default` NAT network are expected (the installer can create the pool with `--create-pool`). `FAIL` is never overridden; `NOT_READY` means something is missing that the install can proceed without (`--allow-not-ready`).

## 3. Install
Print the plan, read it, then apply:
```
sudo bin/svavyom-ctl install --artifact . --create-pool --tls-self-signed HOST.example \
     --enable-mutation --enable-console --backup-dir /var/lib/svavyom/backups            # plan only
sudo bin/svavyom-ctl install --artifact . --create-pool --tls-self-signed HOST.example \
     --enable-mutation --enable-console --backup-dir /var/lib/svavyom/backups --apply
```
It creates the service accounts and directories (root-owned trust anchors, separate runtime state), installs the seven binaries into `/usr/libexec/svavyom`, the web assets into `/usr/share/svavyom/web` and five systemd units, writes `/etc/svavyom/provision.json` **only if it does not exist**, optionally creates a self-signed certificate, starts agent, mutation, offsite, console and API in that order, waits for health and validates the configuration. It never runs a service as root, never opens a firewall port, never edits libvirt security settings and never touches existing VMs, pools or networks.

Options you will likely want:
* `--enable-mutation` lets the console create and manage VMs and `--enable-console` allows the serial and graphical consoles. **Both are off unless you ask**; without them Svavyom is a read-only viewer.
* `--listen ADDR` (default `0.0.0.0:8443`; a non-loopback address needs TLS). For a first look use `--listen 127.0.0.1:8443` and reach it with an SSH tunnel (`ssh -L 8443:127.0.0.1:8443 you@host`); a loopback listener may run without TLS.
* `--enable-nightly-boot HH:MM` runs a nightly check that creates, boots and deletes a disposable VM and raises an alert if it fails.
* `--network`, `--pool` to use names other than the defaults.

## 4. After the install
1. **Create the administrator** (once; the password file is yours, delete it afterwards):
   `sudo -u svavyom-api /usr/libexec/svavyom/api bootstrap-admin --db /var/lib/svavyom/api/svavyom.db --username admin < PASSWORD_FILE`
2. **Import a base image** (an Ubuntu or Debian cloud image in qcow2 format that you downloaded and checked yourself), as root:
   `sudo /usr/libexec/svavyom/api register-image --provision-config /etc/svavyom/provision.json --id ubuntu-24.04 --display-name "Ubuntu 24.04" --distribution Ubuntu --version 24.04 --source /abs/path/noble-server-cloudimg-amd64.img --login-user ubuntu --min-disk-gib 3 --cloud-init`
   Svavyom never downloads or uploads images; an image becomes offered for new VMs when you mark it qualified after a real boot and login test ([`VM-CREATION.md`](https://github.com/Svavyom/svavyom-docs/blob/main/VM-CREATION.md), "Image states": `api image-state --state qualified --evidence REF`).
3. `svavyom-ctl validate-config` and `svavyom-ctl status` should both report PASS.
4. Open `https://HOST:8443/` (or your tunnel) and sign in as `admin`. A self-signed certificate triggers a browser warning; install your own certificate for anything beyond a lab.
5. Read `USING.md`.

## 5. Upgrade, roll back, uninstall
* Upgrade: `sudo bin/svavyom-ctl upgrade --artifact NEW_DIR --enable-mutation --enable-console --backup-dir DIR --listen ADDR [--enable-nightly-boot HH:MM]` (plan) then `--apply`. **Repeat the options you installed with:** an omitted `--listen` falls back to the default and can leave the service unable to start; the upgrade rolls itself back if it does not become healthy. A backup of binaries, units and the database is kept for `sudo svavyom-ctl rollback [--backup ID] --apply` ([`UPGRADE-ROLLBACK.md`](https://github.com/Svavyom/svavyom-docs/blob/main/UPGRADE-ROLLBACK.md)). The tool refuses an older artifact.
* Uninstall: `sudo svavyom-ctl uninstall --apply` removes the binaries, web assets and units and **keeps** configuration, database, VM disks, images and backups. `--purge --confirm-purge DELETE-SVAVYOM-DATA` also removes Svavyom's own configuration, database and service accounts. It never deletes the libvirt pool, image store, VM disks or backups.

## 6. Where things are
| What | Where |
|---|---|
| Binaries | `/usr/libexec/svavyom/` |
| Web console | `/usr/share/svavyom/web/` |
| Configuration | `/etc/svavyom/provision.json`; drop-ins in `/etc/systemd/system/svavyom-api.service.d/` |
| Data | `/var/lib/svavyom/` (database, images, state, database backups, upgrade backups) |
| Logs | the journal: `journalctl -u svavyom-api -u svavyom-agent -u svavyom-mutation -u svavyom-console` |
| Support | `sudo svavyom-ctl support-bundle --out DIR` writes a scrubbed diagnostic archive (read it before you share it) |

More: [`OPERATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/OPERATIONS.md) (health, typed findings, users, database copies, off-host backups), [`UBUNTU-DEPLOYMENT.md`](https://github.com/Svavyom/svavyom-docs/blob/main/UBUNTU-DEPLOYMENT.md) (layout and hardening), [`SUPPORT-BUNDLE.md`](https://github.com/Svavyom/svavyom-docs/blob/main/SUPPORT-BUNDLE.md).

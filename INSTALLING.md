# Installing Svavyom

**Svavyom is a Development Preview / Pre-Alpha.** One host, **Ubuntu 24.04 LTS, x86_64, KVM, libvirt `qemu:///system`**. Use it to evaluate and for non-critical work; read [Known limitations](https://docs.svavyom.com/known-limitations/) first. The installer is `svavyom-ctl`; **every command that changes the host prints its plan and changes nothing until you add `--apply`.**

## 1. Get the release and check it
From the project's releases page download the archive `svavyom-<version>.tar.gz` and its `SHA256SUMS`. Releases from 0.1.0-preview.16 are **signed** (earlier ones are not). Whatever its signature, first check the files against the checksums, and obtain those over a channel you trust (the release page and, ideally, a second source):
```
tar xzf svavyom-<version>.tar.gz && cd svavyom-<version>
sha256sum -c SHA256SUMS                               # every file, nothing unlisted
bin/svavyom-ctl verify-artifact .                     # the same, plus no symlink, no unexpected file
```
Those two checks only compare the files with the manifest **inside** the artifact, which proves nothing about who made it. A signed release also comes with a directory of signatures (for example `sigs/`) and the maintainer's public key, whose fingerprint you compare with the one in the project README and release notes (`ci/sign/README.md`). **Verify the signature before you run anything from the artifact**, with the `svavyom-ctl` already installed on the host or with OpenSSL (steps in `ci/sign/README.md`), then pass both to `install` and `upgrade`:
`--signatures sigs --public-key release-signing-key.pub`. Without them `install` and `upgrade` refuse the artifact. For an artifact you built or checked yourself, `--allow-unsigned` installs it only if it sits where nobody but root can change it (every directory above it and every file in it owned by root and not writable by others): copy it there first, for example `sudo install -d -m 0755 /opt/svavyom-artifacts && sudo cp -a svavyom-<version> /opt/svavyom-artifacts/ && sudo chown -R root:root /opt/svavyom-artifacts`.
Or build it yourself from the source (`BUILDING.md`).

## 2. Prepare the host
```
sudo apt install qemu-system-x86 libvirt-daemon-system libvirt-clients
sudo systemctl enable --now libvirtd
bin/svavyom-ctl preflight            # read-only: PASS / FAIL / NOT_READY with typed findings ([Operations](https://docs.svavyom.com/operations/upgrade/))
```
You need: hardware virtualization enabled (VT-x/AMD-V; `/dev/kvm` present), AppArmor enabled, at least 30 GiB free under `/var/lib`, and a user with `sudo`. A libvirt storage pool and the `default` NAT network are expected (the installer can create the pool with `--create-pool`). `FAIL` is never overridden; `NOT_READY` means something is missing that the install can proceed without (`--allow-not-ready`).

## 3. Install
Print the plan, read it, then apply:
```
sudo bin/svavyom-ctl install --artifact . --signatures SIGS --public-key release-signing-key.pub --create-pool --tls-self-signed HOST.example \
     --enable-mutation --enable-console --backup-dir /var/lib/svavyom/backups            # plan only
sudo bin/svavyom-ctl install --artifact . --signatures SIGS --public-key release-signing-key.pub --create-pool --tls-self-signed HOST.example \
     --enable-mutation --enable-console --backup-dir /var/lib/svavyom/backups --apply
```
It creates the service accounts and directories (root-owned trust anchors, separate runtime state), installs the seven binaries into `/usr/libexec/svavyom`, the web assets into `/usr/share/svavyom/web` and five systemd units, writes `/etc/svavyom/provision.json` **only if it does not exist**, optionally creates a self-signed certificate, starts agent, mutation, offsite, console and API in that order, waits for health and validates the configuration. It never runs a service as root, never opens a firewall port, never edits libvirt security settings and never touches existing VMs, pools or networks.

Options you will likely want:
* `--enable-mutation` lets the console create and manage VMs and `--enable-console` allows the serial and graphical consoles. **Both are off unless you ask**; without them Svavyom is a read-only viewer.
* `--listen ADDR` (default `0.0.0.0:8443`; a non-loopback address needs TLS). For a first look use `--listen 127.0.0.1:8443` and reach it with an SSH tunnel (`ssh -L 8443:127.0.0.1:8443 you@host`); a loopback listener may run without TLS.
* `--enable-nightly-boot HH:MM` runs a nightly check that creates, boots and deletes a disposable VM and raises an alert if it fails.
* `--network`, `--pool` to use names other than the defaults.

### Where VM disks live
VM disks and their cloud-init seeds are kept in a libvirt **directory pool**. By default that is the pool `svavyom` on `/var/lib/svavyom/pool` (root-owned, mode 0711; only libvirt writes there. The API, agent, console and off-host copy services cannot see the directory at all; the mutation service can see that a volume exists and what it is, because it must check the disk it has just made, but it cannot read any volume, which is root-only). `--create-pool` defines it for you.

If `/var/lib` is small, keep the disks on a larger disk instead: define your own libvirt directory pool there first, then give its name with `--pool NAME` and leave out `--create-pool` (an existing pool is used as it is and never changed). The name ends up in `/etc/svavyom/provision.json` as `pool`. `/var/lib/svavyom/pool` is then created but stays **empty**, which is expected and not an error. Check which pool is in use with `sudo virsh pool-list --all` and `grep pool /etc/svavyom/provision.json`.

Images are separate: they live in `/var/lib/svavyom/images`, which is fixed.

### Running behind a TLS proxy
By default Svavyom serves HTTPS itself. If you already run a reverse proxy that terminates TLS (nginx, Caddy), you can instead let Svavyom listen on loopback in plain HTTP and put the proxy in front. Three things must be true, or sign-in throttling and the audit trail will see every visitor as the proxy:
1. Install with `--listen 127.0.0.1:8443` (a loopback listener needs no TLS) and add `--behind-tls-proxy` to the API's command line. The installer has no flag for it; use a systemd drop-in that clears and repeats the whole `ExecStart` (an empty `ExecStart=` line, then the command from `systemctl cat svavyom-api` with the flag appended), for example `/etc/systemd/system/svavyom-api.service.d/zz-proxy.conf` (the `zz-` makes it sort after the installer's own `features.conf`), then `sudo systemctl daemon-reload && sudo systemctl restart svavyom-api`. A drop-in that repeats `ExecStart` does not follow later upgrades: after every upgrade compare it with `systemctl cat svavyom-api`.
2. The proxy sets `X-Forwarded-Proto: https` (so the session cookie is `Secure`) and the **client's address** in a header that the client cannot forge: by default `X-Forwarded-For`, and Svavyom reads only its **rightmost** entry, the one your proxy wrote itself. For another header (for example `CF-Connecting-IP`), pass `--proxy-address-header NAME`; trust such a header only if your proxy overwrites it.
3. The proxy passes WebSocket upgrades (the consoles) and the original `Host`, and allows a long read time.

nginx, as a minimal example (an illustration, not tested against every proxy version):
```
location / {
    proxy_pass http://127.0.0.1:8443;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;
}
```
Caddy: `reverse_proxy 127.0.0.1:8443` is enough (it sets both headers and passes WebSockets).

What this mode trusts: Svavyom believes the client-address header only on a connection that comes from loopback, and any process on the host can connect to the loopback listener and claim any address. Use this mode on a host where only software you trust runs. Without `--behind-tls-proxy` the header is never read.

### Locked out of sign-in
After five failed sign-ins for a user from one address, that **pair** is blocked for 30 seconds, then longer on each further failure up to 15 minutes. Someone else failing for your user name from another address does not lock you out; one address that fails twenty times across any names is blocked on its own; and a user name that has failed recently from anywhere makes the next attempts wait up to two seconds, but a correct password is still accepted. The blocks are held in the API's memory, so there is no per-user unlock: `sudo svavyom-ctl user-unlock --apply` restarts the API and clears them all (signed-in sessions stay valid); `sudo svavyom-ctl user-unlock` alone prints what it would do.

## 4. After the install
1. **Create the administrator** (once; the password file is yours, delete it afterwards):
   `sudo -u svavyom-api /usr/libexec/svavyom/api bootstrap-admin --db /var/lib/svavyom/api/svavyom.db --username admin < PASSWORD_FILE`
2. **Import a base image** (an Ubuntu or Debian cloud image in qcow2 format that you downloaded and checked yourself), as root:
   `sudo /usr/libexec/svavyom/api register-image --provision-config /etc/svavyom/provision.json --id ubuntu-24.04 --display-name "Ubuntu 24.04" --distribution Ubuntu --version 24.04 --source /abs/path/noble-server-cloudimg-amd64.img --login-user ubuntu --min-disk-gib 3 --cloud-init`
   Svavyom never downloads or uploads images; an image becomes offered for new VMs when you mark it qualified after a real boot and login test ([Creating and managing VMs](https://docs.svavyom.com/using/vms/), "Image states": `api image-state --state qualified --evidence REF`).
3. `svavyom-ctl validate-config` and `svavyom-ctl status` should both report PASS.
4. Open `https://HOST:8443/` (or your tunnel) and sign in as `admin`. A self-signed certificate triggers a browser warning; install your own certificate for anything beyond a lab.
5. Read `USING.md`.

## 5. Upgrade, roll back, uninstall
* Upgrade: `sudo bin/svavyom-ctl upgrade --artifact NEW_DIR --signatures SIGS --public-key release-signing-key.pub --enable-mutation --enable-console --backup-dir DIR --listen ADDR [--enable-nightly-boot HH:MM]` (plan) then `--apply`. **Repeat the options you installed with:** an omitted `--listen` falls back to the default and can leave the service unable to start; the upgrade rolls itself back if it does not become healthy. A backup of binaries, units and the database is kept for `sudo svavyom-ctl rollback [--backup ID] --apply` ([Upgrade and rollback](https://docs.svavyom.com/operations/upgrade/)). The tool refuses an older artifact. **A rollback across a database change** (the auth schema moved in preview.18, for example) is refused unless you give `--restore-db`, which puts back the database copy made before the upgrade: users, keys and settings made since then are lost. Without a schema change `rollback` needs no copy. **After a host reboot** Svavyom's services come back by themselves but VMs that were running stay stopped: start them from the console.
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

More: [Operations](https://docs.svavyom.com/operations/upgrade/) (health, typed findings, users, database copies, off-host backups), [Installing on Ubuntu](https://docs.svavyom.com/getting-started/install/) (layout and hardening), [Troubleshooting and support bundles](https://docs.svavyom.com/using/troubleshooting/).

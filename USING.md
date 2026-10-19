# Using Svavyom

This guide is for the person who runs a server with Svavyom installed (`INSTALLING.md`). **Svavyom is a Development Preview / Pre-Alpha**: read [`KNOWN-LIMITATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/KNOWN-LIMITATIONS.md) and keep your own backups of anything that matters.

## 1. Sign in and find your way
Open `https://HOST:8443/` (or the SSH tunnel you made) and sign in. The menu has:

| Page | What it is for |
|---|---|
| **Dashboard** | the host's health, capacity, a one-hour usage graph, open alerts, the last nightly boot check, and what is blocking VM creation, if anything |
| **Virtual machines** | every VM Svavyom manages, with state, address, size and usage; open one for its actions |
| **Create** | make a new VM |
| **Storage and recovery** | images, data volumes, snapshots, backups, restore, and the off-host backup targets |
| **Networks** | managed NAT networks, the host's own networks (read-only), and the **Host bridge** card |
| **Alerts** | disk-space and other alerts, and whether the webhook is configured |
| **Activity** | every operation: who did what, when and how it ended |

There are three roles. A **viewer** can look at everything. An **operator** can also create, start, stop, snapshot, back up, restore and delete VMs and open consoles. An **admin** can also manage networks, delete a backup and use the other admin-only actions. Users are managed on the host with `api user-add|user-list|user-role|user-disable|user-enable|user-passwd` ([`OPERATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/OPERATIONS.md)). Buttons you may not use are not shown.

## 2. Create a VM
You need an image first (`INSTALLING.md`, section 4). If creation is blocked the Dashboard says why in plain words (for example "VM creation is not enabled on this installation" or "no usable image").
1. **Create**. Choose a name (lower-case letters, digits and hyphens), an image, the number of vCPUs, memory and root-disk size from the offered choices, and a network (the default, or one you made).
2. Paste **one public SSH key** (the line from your `id_ed25519.pub`). It is the only way to log in: password login is off. The review screen shows the key's fingerprint; compare it with `ssh-keygen -lf your-key.pub`.
3. Submit. The operation runs in the background and you can watch it; when it ends the VM is **Stopped**. Press **Start**.
4. When the VM has an address, log in: `ssh -i your-key ubuntu@ADDRESS` (the login user is shown with the image; add `-J you@host` if your workstation cannot reach the VM's network).

A VM is also created with an installation-media option: choose an ISO instead of a cloud image to install an operating system by hand (see section 5).

## 3. Everyday actions on a VM
Open the VM from **Virtual machines**. Depending on its state and your role you will see:
* **Start, Stop** (graceful), **Reboot**, **Force off** (like pulling the plug), **Delete** (only a stopped VM; asks first; removes its disks).
* **Resize** the root disk (grow only, only when the VM has no snapshot) and change vCPUs and memory (only while stopped).
* **Snapshot** and restore a snapshot; **Back up**; **Restore** a backup as a new VM.
* **Reserve an address** on a managed network so the VM always gets the same IP from the network's DHCP.
* **Backup schedule**: back the VM up every N hours or daily at a time, keep the last N. **Note:** a scheduled backup is a maintenance window: the VM is **stopped** during it and started again afterwards. The console says so before you save.
* **Console**: a serial console in the browser (text, available while the VM runs) and a **Graphical console** (VNC, for installers and for guests with a display). One viewer at a time.

## 4. Storage, backups and recovery
* **Images** are imported by the host administrator (they are never uploaded or downloaded by the browser).
* **Data volumes**: create, attach to a stopped VM, detach, delete.
* **Backups** are kept on the host. For protection against losing the host, declare **off-host targets** (a mounted directory or an SSH server whose host key you pinned) in `/etc/svavyom/provision.json` and copy a backup there from its page; copies are verified by SHA-256 but are **not encrypted** by Svavyom ([`STORAGE-RECOVERY.md`](https://github.com/Svavyom/svavyom-docs/blob/main/STORAGE-RECOVERY.md)).
* **The database** has its own consistent copies: `sudo svavyom-ctl db-backup`, `db-backups`, `db-restore` ([`OPERATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/OPERATIONS.md)).
* The backup of a **running** VM is not supported yet; stop it first (or use a schedule).

## 5. Installation media, the graphical console and rescue
* Register an ISO as root: `sudo /usr/libexec/svavyom/api register-image --media iso --source /abs/file.iso --id ID --display-name NAME --distribution D --version V --min-disk-gib N --provision-config /etc/svavyom/provision.json`.
* On a **stopped** VM, **Attach media** and choose whether it boots first (installer) or the disk does; **Eject** gives the definition back exactly as it was.
* **Rescue mode** boots a catalog ISO (a live Linux, for example) with the VM's own disk attached as a second disk, so you can repair a bootloader or copy data out; **Leave rescue mode** restores the VM. **Svavyom does not reset a lost password or key for you yet**; rescue mode is the way in, using your own tools.
* Windows guests need drivers and settings Svavyom does not provide yet ([`KNOWN-LIMITATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/KNOWN-LIMITATIONS.md)).

## 6. Networks
* The **default** network and other networks on the host are shown read-only and never changed.
* **Create a managed NAT network** (a private range, a DHCP range): its VMs reach outside through the host and can be reached from the host.
* **Host bridge** (optional, advanced): put the server's own uplink on a bridge so a VM can sit on the host's real network. Changing a host's network can lock you out, so all of it is done on the host with `svavyom-ctl bridge plan|apply|confirm|rollback` and **the old configuration comes back by itself unless you confirm in time**. Read [`BRIDGE.md`](https://github.com/Svavyom/svavyom-docs/blob/main/BRIDGE.md) before you try it. The console shows the state and the countdown; once a bridge is active an admin can create a **bridge network** on it. Svavyom does not know the addresses of VMs on a bridge network.

## 7. Alerts and checks
Alerts warn about low free space on the VM pool and the backup store, high host memory use, a crashed or unexpectedly stopped VM, an operation that gave up, a failed scheduled backup and a failed nightly boot check. Open alerts show in the header; acknowledge them on the Alerts page. One **webhook** (configured in `provision.json`, never in the browser) can receive them ([`ALERTS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/ALERTS.md)). The **nightly boot check** creates, boots and deletes a disposable VM ([`NIGHTLY-BOOT.md`](https://github.com/Svavyom/svavyom-docs/blob/main/NIGHTLY-BOOT.md)).

## 8. When something goes wrong
* The page shows a plain-language error and, for server errors, a correlation id; the same id is in the journal.
* `sudo svavyom-ctl status` and `sudo svavyom-ctl validate-config` say what is wrong with the installation in typed findings; [`OPERATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/OPERATIONS.md) explains each.
* An operation that failed or was interrupted shows on **Activity**; most can be retried and repeat exactly the same request.
* `sudo svavyom-ctl support-bundle --out DIR` writes a scrubbed archive for a bug report; read it before you share it.

## 9. What it will not do (yet)
One host per installation; no high availability; no live migration; no multi-host management; no live-VM backup; no automatic password or key reset; no Windows profile; no image import or conversion beyond qcow2 and ISO; the release is unsigned. The full list is [`KNOWN-LIMITATIONS.md`](https://github.com/Svavyom/svavyom-docs/blob/main/KNOWN-LIMITATIONS.md).

# Using Svavyom

This guide is for the person who runs a server with Svavyom installed (`INSTALLING.md`). **Svavyom is a Development Preview / Pre-Alpha**: read [Known limitations](https://docs.svavyom.com/known-limitations/) and keep your own backups of anything that matters.

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
| **SSH keys** | the public keys saved for new VMs, and a way to make a key pair in your browser |
| **Users** | (admins only) who can sign in and in which role: add a user, change a role, reset a password, disable or enable |
| **Account** | change your own password |
| **System** | which Svavyom version runs, which services it depends on and whether each answers, and what to do when one does not |

There are three roles. A **viewer** can look at everything. An **operator** can also create, start, stop, snapshot, back up, restore and delete VMs and open consoles. An **admin** can also manage networks, delete a backup and use the other admin-only actions. Users are managed on the host with `api user-add|user-list|user-role|user-disable|user-enable|user-passwd` ([Operations](https://docs.svavyom.com/operations/upgrade/)). Buttons you may not use are not shown.

**Users and passwords.** Everyone can change their own password under **Account**: you type the current one (a wrong guess counts against the same limit as signing in), and your other sessions are signed out while the one you are using stays. An **admin** manages people under **Users**: **Add a user** gives a name, a role and a **temporary password**; the new user must choose their own password when they first sign in, and until they do the console shows only that screen and every other request is refused. **Reset password** does the same for an existing user and signs them out. Changing a role, disabling and resetting also sign the user out. An administrator cannot change their own role, disable or reset themselves here, so the console cannot lock the installation out; the host's `sudo /usr/libexec/svavyom/api user-list | user-add | user-role | user-disable | user-enable | user-passwd` remain the recovery path, and the last enabled administrator can never be demoted or disabled. Give a temporary password to its user through a safe channel: it is shown to nobody afterwards.

## 2. Create a VM
You need an image first (`INSTALLING.md`, section 4). If creation is blocked the Dashboard says why in plain words (for example "VM creation is not enabled on this installation" or "no usable image").
1. **Create**. Choose a name (lower-case letters, digits and hyphens), an image, the number of vCPUs, memory and root-disk size from the offered choices, and a network (the default, or one you made).
2. Choose a **saved key** (see **SSH keys** below) or paste **one public SSH key** (the line from your `id_ed25519.pub`). It is the only way to log in: password login is off. The review screen shows the key's fingerprint; compare it with `ssh-keygen -lf your-key.pub`.
3. Submit. The operation runs in the background and you can watch it; when it ends the VM is **Stopped**. Press **Start**.
4. When the VM has an address, log in: `ssh -i your-key ubuntu@ADDRESS` (the login user is shown with the image; add `-J you@host` if your workstation cannot reach the VM's network).

**SSH keys.** The **SSH keys** page keeps one list of public keys for the whole installation, so you do not paste the key for every VM. Operators and administrators add keys; everyone signed in can see them; an administrator, or the person who added a key, can delete it (VMs already created with it keep it). Svavyom computes each key's fingerprint itself and refuses anything that is not one plain public key (a private key is refused and never echoed; RSA keys under 3072 bits are refused). The same list is offered when you reinstall a VM or restore a backup.

**Making a key pair in the browser.** On the same page, **Make a key pair here** creates an Ed25519 pair on your computer. You download the **private key** once; it is never sent to Svavyom and not stored in the browser or on the server, so keep the file safe (it is not protected by a passphrase: run `chmod 600 FILE`, and `ssh-keygen -p -f FILE` adds one). Only the public key is saved, when you press **Save public key**, which is possible only after the download. The page needs HTTPS (a self-signed certificate that your browser was told to accept is enough); over plain `http://` it says so and you make the key on your own computer with `ssh-keygen -t ed25519`.

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
* **Image rules.** `register-image` refuses anything outside these rules and names the field that failed (it never repeats what you typed):
  * `--id`: use lower-case letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters
  * `--display-name`, `--distribution`, `--version`: start with a letter or digit, then letters, digits, spaces and . _ ( ) + - only, at most 63 characters
  * `--login-user` (cloud images): use lower-case letters, digits, '_' or '-', starting with a letter or '_', at most 32 characters
  * `--min-disk-gib`: use a whole number from 1 to 4096 (GiB)
* **Data volumes**: create, attach to a stopped VM, detach, delete.
* **Backups** are kept on the host. For protection against losing the host, declare **off-host targets** (a mounted directory or an SSH server whose host key you pinned) in `/etc/svavyom/provision.json` and copy a backup there from its page; copies are verified by SHA-256 but are **not encrypted** by Svavyom ([Storage, backups and recovery](https://docs.svavyom.com/using/storage/)).
* **The database** has its own consistent copies: `sudo svavyom-ctl db-backup`, `db-backups`, `db-restore` ([Operations](https://docs.svavyom.com/operations/upgrade/)).
* The backup of a **running** VM is not supported yet; stop it first (or use a schedule).

## 5. Installation media, the graphical console and rescue
* Register an ISO as root: `sudo /usr/libexec/svavyom/api register-image --media iso --source /abs/file.iso --id ID --display-name NAME --distribution D --version V --min-disk-gib N --provision-config /etc/svavyom/provision.json`.
* On a **stopped** VM, **Attach media** and choose whether it boots first (installer) or the disk does; **Eject** gives the definition back exactly as it was.
* **Rescue mode** boots a catalog ISO (a live Linux, for example) with the VM's own disk attached as a second disk, so you can repair a bootloader or copy data out; **Leave rescue mode** restores the VM. **Svavyom does not reset a lost password or key for you yet**; rescue mode is the way in, using your own tools.
* Windows guests need drivers and settings Svavyom does not provide yet ([Known limitations](https://docs.svavyom.com/known-limitations/)).

## 6. Networks
* The **default** network and other networks on the host are shown read-only and never changed.
* **Create a managed NAT network** (a private range, a DHCP range): its VMs reach outside through the host and can be reached from the host.
* **Host bridge** (optional, advanced): put the server's own uplink on a bridge so a VM can sit on the host's real network. Changing a host's network can lock you out, so all of it is done on the host with `svavyom-ctl bridge plan|apply|confirm|rollback` and **the old configuration comes back by itself unless you confirm in time**. Read [Networks and the host bridge](https://docs.svavyom.com/using/networks/) before you try it. The console shows the state and the countdown; once a bridge is active an admin can create a **bridge network** on it. Svavyom does not know the addresses of VMs on a bridge network.

## 7. Alerts and checks
Alerts warn about low free space on the VM pool and the backup store, high host memory use, a crashed or unexpectedly stopped VM, an operation that gave up, a failed scheduled backup and a failed nightly boot check. Open alerts show in the header; acknowledge them on the Alerts page. One **webhook** (configured in `provision.json`, never in the browser) can receive them ([Alerts](https://docs.svavyom.com/using/alerts/)). The **nightly boot check** creates, boots and deletes a disposable VM ([Alerts and the nightly boot check](https://docs.svavyom.com/using/alerts/)).

## 8. When something goes wrong
* The **System** page names the Svavyom version and each service it depends on (the web console and API, the host agent, the mutation service, the console broker and the off-host backup service) and says whether each one **answers**, **does not answer** or is **turned off**. For a service that does not answer it shows the commands to run on the host. It reports what the API can see: it connects to each service and does not read the service's systemd state, which `sudo svavyom-ctl status` does.
* The page shows a plain-language error and, for server errors, a correlation id; the same id is in the journal.
* `sudo svavyom-ctl status` and `sudo svavyom-ctl validate-config` say what is wrong with the installation in typed findings; [Operations](https://docs.svavyom.com/operations/upgrade/) explains each.
* An operation that failed or was interrupted shows on **Activity**; most can be retried and repeat exactly the same request.
* `sudo svavyom-ctl support-bundle --out DIR` writes a scrubbed archive for a bug report; read it before you share it.

## 9. What it will not do (yet)
* One host per installation; no high availability, live migration or multi-host management.
* **VMs are not started again after the host reboots.** They keep their disks and data; start them from the console. (Svavyom's own services and libvirt's network and pool do come back by themselves.)
* No live-VM backup: a backup, a scheduled backup and a restore of a VM work on a **stopped** VM. A restore always makes a **new** VM.
* The Windows guest profile is Windows Server 2019 (evaluation) on BIOS, a SATA disk and an Intel e1000e card only; no UEFI, TPM, Windows 11 or virtio disk or network. A second installation medium is a data medium: it never boots.
* No image download, import or conversion beyond qcow2 and ISO; images are registered on the host by root.
* Local users with three fixed roles; no single sign-on, no second factor, no per-VM grants. Passwords are reset by an administrator (a temporary one) or on the host; the person's SSH key is not reset for them (rescue mode is the way in).
* The web console's certificate is self-signed unless you install your own.
* **Rolling back across a database change** (preview.18 to preview.17, for example) is possible only with the pre-upgrade database copy, which loses the users, keys and settings made since the upgrade; the installer refuses the rollback otherwise and says so.
* Releases from 0.1.0-preview.16 are signed; verify before you install (`INSTALLING.md`).

The full list is [Known limitations](https://docs.svavyom.com/known-limitations/).

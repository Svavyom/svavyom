# Changelog

What changed in each release, in words an operator can use. The version is in `VERSION` and in `svavyom-ctl version`. Releases from **0.1.0-preview.16** are signed with the maintainer's Ed25519 key (fingerprint `247e9193c933b6fa`, `ci/sign/README.md`); earlier ones are not. An upgrade across a database change can only be rolled back with the pre-upgrade database copy (`INSTALLING.md`, section 5): the entries that say "database" below are those.

## 0.1.0-preview.18 (2026-11-13)
* **Users and passwords in the console.** Everyone can change their own password under **Account** (the current one is checked under the same limit as sign-in, and your other sessions are signed out). Administrators manage people under **Users**: add a user, change a role, reset a password, disable and enable. A new user and a reset get a **temporary password** that must be changed at the next sign-in; until then the console shows only that screen and the API refuses everything else. An administrator cannot change themselves from the console (the host's `api user-*` commands stay the recovery path).
* **SSH keys.** One list of saved public keys for the installation, offered when you create, reinstall or restore a VM, so the key is not pasted each time. **Make a key pair here** creates an Ed25519 pair in your browser: the private key is a one-time download that is never sent to Svavyom or stored. The server validates every key and refuses a private key.
* **Database:** a new migration (the "must change password" flag and the saved keys). Rolling back to preview.17 needs `--restore-db` and loses users and keys created since the upgrade.
* The Go toolchain moves to 1.27.4 (a standard-library advisory in `net/http`).

## 0.1.0-preview.17 (2026-11-11)
* **System page.** Which Svavyom version runs, since when, which services it depends on (web console and API, host agent, mutation, console broker, off-host backup), whether each answers, and the exact commands to run on the host when one does not.
* The dashboard shows the real version (it showed `dev`: the release build stamped only `svavyom-ctl`).
* On the VM list, when creating a VM is not possible the page now says why and shows the `register-image` command (a fresh install has no image).
* The signing key was replaced; the first key's passphrase had been lost and it never signed a release.

## 0.1.0-preview.16 (2026-11-08) — first signed release
* **A create on the packaged default pool no longer fails** with `conflict`: the mutation service can see the pool again (found by the clean-host run).
* `svavyom-ctl backup-report` lists what the old retention bug left on disk.
* How to run behind a TLS proxy, and the sign-in lockout, are documented (`INSTALLING.md`).

## 0.1.0-preview.15 (2026-11-06)
* **`install` and `upgrade` authenticate the artifact.** They need `--signatures DIR --public-key FILE`, or `--allow-unsigned` for an artifact that sits where only root can change it. Files are read once and hashed at the point of use.
* A key generator and signing scripts, proven against the installer (`ci/sign/`).

## 0.1.0-preview.14 (2026-11-05)
* **Sign-in throttling** that a stranger cannot use to lock the owner out (keyed on user and source together), with the right client address behind a proxy; `svavyom-ctl user-unlock`.
* Authentication audit events name the user, and a failed audit write is no longer silent (it raises a critical alert).
* An administrator can cancel an operation that used all its attempts.
* Only operators read a VM's serial boot output, and only with the console switch on.
* Off-host backup import is bounded and verified before it is listed; backup retention never forgets what it cannot list; replaying a Snapshot request returns the original operation.
* Fixes in the media dialog, and how to boot from a second medium.

## 0.1.0-preview.13 (2026-10-31)
* **Windows guest profile** (Windows Server 2019 evaluation, BIOS, SATA disk, Intel e1000e network card; qualified on a real host) and **more than one installation medium** per VM (the second is a data medium, for example the driver ISO).
* `register-image` names the field and the rule that failed; the create wizard describes the graphical console.

## 0.1.0-preview.12 (2026-10-19)
* The first published preview (unsigned).

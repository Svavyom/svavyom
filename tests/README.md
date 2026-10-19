# Automated test layers
T0: unit/contract/property/negative (PR); T1: fake libvirt driver, UI E2E, mocked filesystem/network (PR/nightly); T2: actual VM in nested KVM or QEMU emulation (nightly); T3: bare-metal host qualifying every stable release (human authorized); T4: distro/cpu matrix periodic.
**Warning:** libvirt test:///default is in-memory fake; passing it does not demonstrate a bootable VM. Each report tags environment_class and exact kernel/libvirt/QEMU image SHA. No real host network rewrites in CI.

**Canonical tiers and evidence (M0-E02-S04):** see `docs/EVIDENCE.md`. Every test file is classified in `contracts/evidence/test-classes.json`; evidence records state tier, environment class (`simulated`/`emulated`/`nested`/`bare_metal`), revision and provenance, and are checked by `make evidence`.

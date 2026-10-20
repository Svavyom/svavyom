# Contributing

Thank you for looking. Svavyom is a Development Preview run by a small team, so this page is short and honest.

## Right now
* **Issues** (bugs, questions, ideas) are welcome. Please say which version (`svavyom-ctl version`) and what your host is.
* **Pull requests are not accepted yet.** Outside contributions need a signed **contributor licence agreement** (`CLA.md`) so that the project can keep offering the code under its licences and, where needed, under others (`LICENSING.md`). The agreement text is being reviewed by counsel and the automated signing flow is not set up. When it is, this page will say so and pull requests will be welcome.
* **Security reports** go through `SECURITY.md`, not through issues.

## When contributions open
1. Read `BUILDING.md` and make `make docker-check` pass on your change (some gates need the separate requirements repository and are marked in `BUILDING.md`).
2. Keep a change small and say why. A change that touches VM creation also repeats the real-host steps of [Contributing](https://docs.svavyom.com/development/contributing/).
3. The open-core rules apply: nothing in this repository may add a licence key, trial, host or VM limit, entitlement check or call home (`release/open-core.json`).
4. New dependencies need a licence on the approved list ([Licensing and dependencies](https://docs.svavyom.com/licensing/)).
5. By contributing you agree to the contributor licence agreement.

## Conduct
Be kind and be specific. Harassment and personal attacks are not welcome and will get a contributor removed.

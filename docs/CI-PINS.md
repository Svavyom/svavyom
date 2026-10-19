# Verified GitHub Actions pins (story M0-E02-S02)
Every `uses:` in `.github/workflows/` must appear here; `make ci-policy` enforces it.
Add or change a row only in a reviewed PR after verifying the tag-to-commit
mapping against the upstream repository.

| Action | Commit SHA | Tag | Verified | Method |
|---|---|---|---|---|
| actions/checkout | 3d3c42e5aac5ba805825da76410c181273ba90b1 | v7.0.1 | 2026-10-04 | `GET https://api.github.com/repos/actions/checkout/git/ref/tags/v7.0.1` → lightweight tag, object type `commit`, SHA as listed |

Update policy: no automated bot updates until maintainers choose one (e.g.
Dependabot with SHA pinning) in a reviewed story; re-verify on every change.

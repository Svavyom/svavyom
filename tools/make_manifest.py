#!/usr/bin/env python3
"""The release manifest, made from the files (story M0-E01-S20; the shape the owner approved on 2026-11-14 in operations/RELEASE-MANIFEST-CANDIDATE-preview.18.md).

    python3 tools/make_manifest.py --artifact release-out/svavyom-VERSION --signatures release-out/sigs-N --public-key ci/sign/release-signing-key.pub \\
        --gate-log FULL-GATE.log [--browser-log BROWSER.log] --ci-run URL --ci-conclusion success --docs-repo ../svavyom-product --out DIR [--archive FILE] [--ctl svavyom-ctl] \\
        [--merge-commit SHA] [--evidence PATH ...] [--blockers DR-034,DR-042]

It reads the artifact (MANIFEST.json, SHA256SUMS, the SBOM files), the signing record, the full local gate log, the repository (docs-lock.json, the review-findings list)
and the private requirements repository (the decisions and stories the release depends on), recomputes every digest, and writes RELEASE-MANIFEST-VERSION.md and .json.
It refuses, with a typed finding and no output, when an input is missing or disagrees with another: a digest that does not match, a signing record that does not describe
this artifact, a key whose fingerprint is not the one recorded, a gate log that does not end in "all gates passed", a CI run that did not pass, a commit or docs pin that
the repositories do not know. The sign-off lines stay empty for a human. Standard library only; nothing is sent anywhere. Real host names, addresses and run ids belong
in the output (which goes to the private repository), never in this tool or its tests.
"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

CODES = ("MISSING_INPUT", "DIGEST_MISMATCH", "SIGNING_INFO_MISMATCH", "FINGERPRINT_MISMATCH", "GATE_NOT_PASSED", "CI_NOT_PASSED", "COMMIT_UNKNOWN", "DOCS_PIN_UNKNOWN",
         "VERIFY_FAILED", "BAD_INPUT")
SBOM_FILES = ("docs/sbom/sbom.cdx.json", "docs/sbom/licenses.json", "THIRD-PARTY-NOTICES.md")  # in the artifact
REPO_SBOM_FILES = ("docs/sbom/go-modules.txt",)  # in the repository, at the commit the artifact was built from (the working tree here)
DEFAULT_BLOCKERS = ("DR-034", "DR-042")


class Findings(Exception):
    def __init__(self, items):
        super().__init__("; ".join("%s %s" % i for i in items))
        self.items = items


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def key_fingerprint(pub_pem):
    """The first 16 hex digits of the SHA-256 of the DER public key: what `openssl pkey -pubin -pubout -outform DER | sha256sum | cut -c1-16` prints."""
    m = re.search(r"-----BEGIN PUBLIC KEY-----\s*(.*?)\s*-----END PUBLIC KEY-----", pub_pem, re.S)
    if not m:
        raise ValueError("not a PEM public key")
    return hashlib.sha256(base64.b64decode("".join(m.group(1).split()))).hexdigest()[:16]


def summarize_gate_log(text):
    """What the full gate log says: it passed, and how many tests each tier ran. Expected-negative output (FAIL lines of mutation tests) is not read as a failure; only the
    gate's own last line decides."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)  # vitest colours its summary
    out = {"passed": "make check: all gates passed" in text}
    m = re.findall(r"^\s*Tests\s+(\d+) passed", text, re.M)
    out["frontend_tests"] = max(map(int, m)) if m else None
    m = re.findall(r"^\s*(\d+) passed \(", text, re.M)
    out["browser_passed"] = int(m[-1]) if m else None
    flaky = re.findall(r"^\s*(\d+) flaky", text, re.M)
    out["browser_flaky"] = int(flaky[-1]) if flaky else 0
    out["browser_failed"] = int(re.findall(r"^\s*(\d+) failed", text, re.M)[-1]) if re.search(r"^\s*\d+ failed", text, re.M) else 0
    ran = [(int(n), s) for n, s in re.findall(r"^Ran (\d+) tests? in [0-9.]+s\n\n(OK[^\n]*|FAILED[^\n]*)", text, re.M) if s.startswith("OK")]
    if ran:
        n, s = max(ran)
        sk = re.search(r"skipped=(\d+)", s)
        out["python_tests"], out["python_skipped"] = n, int(sk.group(1)) if sk else 0
    else:
        out["python_tests"], out["python_skipped"] = None, 0
    out["go_packages_ok"] = len(set(re.findall(r"^ok\s+(\S+)\s", text, re.M)))
    return out


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False)  # noqa: S603,S607
    return r.returncode, r.stdout.strip()


def commit_known(repo, sha):
    return bool(re.fullmatch(r"[0-9a-f]{40}", sha or "")) and git(repo, "cat-file", "-e", sha + "^{commit}")[0] == 0


def load_json(path, label, findings):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        findings.append(("MISSING_INPUT", "%s is missing or is not JSON: %s" % (label, path)))
        return None


def collect(a):
    """Every fact of the manifest, or raise Findings."""
    f = []
    art = Path(a.artifact)
    sigs = Path(a.signatures)
    docs = Path(a.docs_repo)
    repo = Path(a.repo)
    man = load_json(art / "MANIFEST.json", "the artifact's MANIFEST.json", f)
    info = load_json(sigs / "SIGNING-INFO.json", "SIGNING-INFO.json", f)
    gate_text = ""
    try:
        gate_text = Path(a.gate_log).read_text(errors="replace")
    except OSError:
        f.append(("MISSING_INPUT", "the gate log is missing: %s" % a.gate_log))
    try:
        pub = Path(a.public_key).read_text()
    except OSError:
        pub = ""
        f.append(("MISSING_INPUT", "the public key is missing: %s" % a.public_key))
    lock = load_json(repo / "docs-lock.json", "docs-lock.json", f)
    findings_list = load_json(repo / "contracts/threats/review-findings.json", "the review-findings list", f)
    index = load_json(docs / "decisions/index.json", "the decision register of the requirements repository", f)
    stories = load_json(docs / "backlog/stories.json", "the story list of the requirements repository", f)
    if f:
        raise Findings(f)
    # the artifact
    sums = art / "SHA256SUMS"
    if not sums.is_file():
        raise Findings([("MISSING_INPUT", "the artifact has no SHA256SUMS")])
    for e in man["files"]:
        p = art / e["path"]
        if not p.is_file() or sha256_file(p) != e["sha256"]:
            f.append(("DIGEST_MISMATCH", "%s does not match MANIFEST.json" % e["path"]))
    sbom = {}
    for rel in SBOM_FILES:
        p = art / rel
        if p.is_file():
            sbom[rel] = sha256_file(p)
        else:
            f.append(("MISSING_INPUT", "the artifact has no %s" % rel))
    for rel in REPO_SBOM_FILES:
        p = repo / rel
        if p.is_file():
            sbom[rel] = sha256_file(p)
        else:
            f.append(("MISSING_INPUT", "the repository has no %s" % rel))
    components = None
    if "docs/sbom/sbom.cdx.json" in sbom:
        try:
            components = len(json.loads((art / "docs/sbom/sbom.cdx.json").read_text())["components"])
        except (ValueError, KeyError):
            f.append(("BAD_INPUT", "docs/sbom/sbom.cdx.json is not a CycloneDX document"))
    sums_sha, man_sha = sha256_file(sums), sha256_file(art / "MANIFEST.json")
    # the signing record
    if info.get("artifact") != "svavyom-" + man["version"] or info.get("SHA256SUMS_sha256") != sums_sha or info.get("MANIFEST_json_sha256") != man_sha:
        f.append(("SIGNING_INFO_MISMATCH", "SIGNING-INFO.json does not describe this artifact's SHA256SUMS and MANIFEST.json"))
    try:
        fp = key_fingerprint(pub)
    except ValueError:
        fp = ""
        f.append(("BAD_INPUT", "the public key is not a PEM public key"))
    if fp and info.get("key_fingerprint") != fp:
        f.append(("FINGERPRINT_MISMATCH", "the public key's fingerprint is %s, the signing record says %s" % (fp, info.get("key_fingerprint"))))
    if a.ctl:
        r = subprocess.run([a.ctl, "verify-artifact", str(art), "--signatures", str(sigs), "--public-key", a.public_key], capture_output=True, text=True, check=False)  # noqa: S603
        if r.returncode != 0 or not r.stdout.startswith("OK artifact"):
            f.append(("VERIFY_FAILED", "svavyom-ctl verify-artifact did not accept the artifact and its signatures"))
    # the gate and CI
    gate = summarize_gate_log(gate_text)
    if a.browser_log:
        try:
            b = summarize_gate_log(Path(a.browser_log).read_text(errors="replace"))
        except OSError:
            f.append(("MISSING_INPUT", "the browser-tier log is missing: %s" % a.browser_log))
            b = None
        if b is not None:
            gate["browser_passed"], gate["browser_flaky"] = b["browser_passed"], b["browser_flaky"]
            if b["browser_failed"] or b["browser_passed"] is None:
                f.append(("GATE_NOT_PASSED", "the browser-tier log shows failures or no result"))
    if not gate["passed"]:
        f.append(("GATE_NOT_PASSED", "the gate log does not say \"make check: all gates passed\""))
    if a.ci_conclusion != "success":
        f.append(("CI_NOT_PASSED", "the CI run is recorded as %s, not success" % a.ci_conclusion))
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/actions/runs/\d+", a.ci_run or ""):
        f.append(("BAD_INPUT", "--ci-run must be a GitHub Actions run URL"))
    # the repositories
    built = man.get("built_from", "")
    if not commit_known(repo, built):
        f.append(("COMMIT_UNKNOWN", "the commit the artifact says it was built from is not in the repository: %s" % built))
    if a.merge_commit and not commit_known(repo, a.merge_commit):
        f.append(("COMMIT_UNKNOWN", "the merge commit is not in the repository: %s" % a.merge_commit))
    pin = lock.get("commit", "")
    if not commit_known(docs, pin):
        f.append(("DOCS_PIN_UNKNOWN", "docs-lock.json pins a commit the requirements repository does not have: %s" % pin))
    newest = git(docs, "rev-parse", "HEAD")[1]
    for e in a.evidence or []:
        if not (docs / e).exists():
            f.append(("MISSING_INPUT", "the evidence path is not in the requirements repository: %s" % e))
    kl = docs / "docs/KNOWN-LIMITATIONS.md"
    if not kl.is_file():
        f.append(("MISSING_INPUT", "docs/KNOWN-LIMITATIONS.md is not in the requirements repository"))
    if f:
        raise Findings(f)
    recs = {r["id"]: r for r in index["decisions"]}
    story_status = {s["id"]: s["status"] for s in (stories["stories"] if isinstance(stories, dict) else stories)}
    blockers = []
    for b in a.blockers:
        r = recs.get(b)
        if r is None:
            raise Findings([("BAD_INPUT", "unknown decision %s" % b)])
        blockers.append({"decision": b, "title": r["title"], "status": r["status"], "options": r["options_chosen"],
                         "stories": {s: story_status.get(s, "unknown") for s in r["stories"] if s.startswith("M0-E01-S1") or s.startswith("M0-E01-S2")}})
    open_findings = [x["id"] + " (" + x["severity"] + ")" for x in findings_list["findings"] if x["status"] == "open"]
    archive = None
    if a.archive:
        ap = Path(a.archive)
        if not ap.is_file():
            raise Findings([("MISSING_INPUT", "the archive is missing: %s" % a.archive)])
        archive = {"name": ap.name, "sha256": sha256_file(ap)}
    return {
        "schema": 1, "product": man["product"], "version": man["version"], "classification": man["classification"], "license": man["license"],
        "built_from": built, "merge_commit": a.merge_commit or None, "docs_pin": pin, "docs_head": newest,
        "artifact": {"directory": art.name, "files": len(man["files"]), "SHA256SUMS_sha256": sums_sha, "MANIFEST_json_sha256": man_sha, "archive": archive},
        "sbom": {"components": components, "files": sbom},
        "signature": {"method": info.get("method"), "key_fingerprint": fp, "signed_at": info.get("signed_at"), "verified_with_ctl": bool(a.ctl)},
        "ci": {"run": a.ci_run, "conclusion": a.ci_conclusion}, "gate": gate, "blockers": blockers, "open_findings": open_findings, "evidence": sorted(a.evidence or []),
        "schema_versions": man.get("schema_versions", {}),
    }


def render(m):
    g, a = m["gate"], m["artifact"]
    L = ["# Release manifest: %s" % m["version"], "",
         "Made by `tools/make_manifest.py` from the artifact, the signing record, the full local gate log and the two repositories. Nothing here is typed by hand except the sign-off lines.", "",
         "## Provenance", "| Item | Value |", "|---|---|",
         "| Product, version, classification | %s %s, %s |" % (m["product"].capitalize(), m["version"], m["classification"]),
         "| Licence | %s |" % m["license"],
         "| Code commit the artifact was built from | `%s`%s |" % (m["built_from"], " (merged to main as `%s`)" % m["merge_commit"] if m["merge_commit"] else ""),
         "| Requirements and evidence repository (private) | pinned by `docs-lock.json` at `%s`; its head when this was made: `%s` |" % (m["docs_pin"], m["docs_head"]),
         "| Artifact | `%s/`, %d files, all digests match `MANIFEST.json` |" % (a["directory"], a["files"]),
         "| `SHA256SUMS` sha256 | `%s` |" % a["SHA256SUMS_sha256"],
         "| `MANIFEST.json` sha256 | `%s` |" % a["MANIFEST_json_sha256"],
         "| Archive | %s |" % ("`%s`, sha256 `%s`" % (a["archive"]["name"], a["archive"]["sha256"]) if a["archive"] else "not made"),
         "| Signature | %s, key fingerprint `%s` (verify the key yourself: `openssl pkey -pubin -in release-signing-key.pub -pubout -outform DER \\| sha256sum \\| cut -c1-16`), signed %s; %s |"
         % (m["signature"]["method"], m["signature"]["key_fingerprint"], m["signature"]["signed_at"],
            "verified with `svavyom-ctl verify-artifact` while this manifest was made" if m["signature"]["verified_with_ctl"] else "the signing record matches the artifact's digests and the key (`svavyom-ctl verify-artifact` was not run by the generator)"),
         "", "## CI and gates", "| Item | Value |", "|---|---|",
         "| CI run on the release head | %s (Quality gates: %s) |" % (m["ci"]["run"], m["ci"]["conclusion"]),
         "| Full local gate (`make docker-check`) | all gates passed (including the governance gates that CI cannot run) |", "",
         "## Bill of materials", "CycloneDX, %s components. SHA-256 of each file:" % (m["sbom"]["components"] if m["sbom"]["components"] is not None else "?"), ""]
    L += ["* `%s`: `%s`" % (k, v) for k, v in sorted(m["sbom"]["files"].items())]
    L += ["", "## Test summaries (from the gate log)", "| Tier | Result |", "|---|---|",
          "| Go, all packages, race detector | %d packages ok |" % g["go_packages_ok"],
          "| Frontend unit | %s |" % ("%d tests pass" % g["frontend_tests"] if g["frontend_tests"] is not None else "not found in the log"),
          "| Browser tier (Playwright) | %s%s |" % ("%d passed" % g["browser_passed"] if g["browser_passed"] is not None else "not run for this manifest (no browser-tier log was given)", ", %d flaky (needed a retry)" % g["browser_flaky"] if g["browser_flaky"] else ""),
          "| Python gate tests (the largest suite) | %s%s |" % ("%d pass" % g["python_tests"] if g["python_tests"] is not None else "not found in the log", " (%d skipped)" % g["python_skipped"] if g["python_skipped"] else ""), ""]
    if m["evidence"]:
        L += ["## Evidence listed by the release manager", ""] + ["* `%s`" % e for e in m["evidence"]] + [""]
    L += ["## Release blockers set by the owner", "| Decision | Status | Options | Stories |", "|---|---|---|---|"]
    for b in m["blockers"]:
        L.append("| %s: %s | %s | %s | %s |" % (b["decision"], b["title"], b["status"], ", ".join("%s=%s" % kv for kv in sorted(b["options"].items())), ", ".join("%s (%s)" % kv for kv in sorted(b["stories"].items()))))
    L += ["", "## Findings of the second security review still open", ", ".join(m["open_findings"]) if m["open_findings"] else "none", "",
          "## Known limitations", "`docs/KNOWN-LIMITATIONS.md` (authoritative) and the public `USING.md` section 9.", "",
          "## Human sign-off", "Release manager: ______________________ Date: __________   Owner: ______________________ Date: __________", ""]
    return "\n".join(L)


def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--signatures", required=True)
    ap.add_argument("--public-key", required=True)
    ap.add_argument("--gate-log", required=True)
    ap.add_argument("--ci-run", required=True)
    ap.add_argument("--ci-conclusion", required=True)
    ap.add_argument("--docs-repo", required=True)
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--out", required=True)
    ap.add_argument("--browser-log", default="", help="the output of make docker-fe-browser (the browser tier is not part of make docker-check)")
    ap.add_argument("--archive", default="")
    ap.add_argument("--ctl", default="")
    ap.add_argument("--merge-commit", default="")
    ap.add_argument("--evidence", action="append", default=[])
    ap.add_argument("--blockers", default=",".join(DEFAULT_BLOCKERS))
    a = ap.parse_args(argv)
    a.blockers = [b for b in a.blockers.split(",") if b]
    return a


def main(argv=None):
    a = parse(argv)
    try:
        m = collect(a)
    except Findings as e:
        for code, detail in e.items:
            print("ERROR %s %s" % (code, detail), file=sys.stderr)
        return 1
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / ("RELEASE-MANIFEST-%s.json" % m["version"])).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    (out / ("RELEASE-MANIFEST-%s.md" % m["version"])).write_text(render(m))
    print("OK wrote RELEASE-MANIFEST-%s.md and .json in %s" % (m["version"], out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

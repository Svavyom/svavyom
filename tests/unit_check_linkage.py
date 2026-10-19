"""Tests for tools/check_linkage.py (story M0-E02-S01, tier T0, simulated).

Every test builds throwaway git repositories in a temporary directory; no
host state, network or privileged access is used.
"""
import contextlib
import shutil
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECKER = Path(__file__).resolve().parents[1] / "tools" / "check_linkage.py"
STORY = "M0-E02-S01"
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
}


def git(repo, *args, stdin=None):
    return subprocess.run(["git", "-C", str(repo), *args], env=GIT_ENV, input=stdin,
                          check=True, capture_output=True).stdout.decode().strip()


def default_backlog():
    stories = [
        {"id": STORY, "status": "ready"},
        {"id": "M0-E02-S02", "status": "proposed"},
    ]
    acs = [{"id": "%s-AC0%d" % (STORY, i), "story_id": STORY} for i in (1, 2, 3, 4)]
    acs.append({"id": "M0-E02-S02-AC01", "story_id": "M0-E02-S02"})
    return stories, acs


def snapshot(repo):
    """Hash every file under the repository (including .git) to detect writes."""
    digest = hashlib.sha256()
    for path in sorted(Path(repo).rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(repo)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


class LinkageFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.docs = self.root / "docs"
        self.platform = self.root / "platform"
        self.docs_sha = self.make_docs(*default_backlog())
        self.platform.mkdir()
        git(self.platform, "init", "-q", "-b", "main")
        (self.platform / "README.md").write_text("baseline\n")
        git(self.platform, "add", "-A")
        git(self.platform, "commit", "-q", "-m", "Baseline: import")
        git(self.platform, "checkout", "-q", "-b", "story")

    def tearDown(self):
        self.tmp.cleanup()

    def make_docs(self, stories, acs, raw_stories=None):
        if not self.docs.exists():
            self.docs.mkdir()
            git(self.docs, "init", "-q", "-b", "main")
        (self.docs / "backlog").mkdir(exist_ok=True)
        (self.docs / "backlog/stories.json").write_text(raw_stories if raw_stories is not None else json.dumps(stories))
        (self.docs / "backlog/acceptance.json").write_text(json.dumps(acs))
        git(self.docs, "add", "-A")
        git(self.docs, "commit", "-q", "--allow-empty", "-m", "docs")
        return git(self.docs, "rev-parse", "HEAD")

    def write_lock(self, commit=None, raw=None):
        content = raw if raw is not None else json.dumps(
            {"schema": 1, "docs_repo": "cloud-product-docs", "commit": commit or self.docs_sha})
        (self.platform / "docs-lock.json").write_text(content)

    def commit(self, trailers=None, body="Implement linkage", lock=True, message=None):
        if lock and not (self.platform / "docs-lock.json").exists():
            self.write_lock()
        (self.platform / "change.txt").write_text(os.urandom(8).hex())
        git(self.platform, "add", "-A")
        if message is None:
            if trailers is None:
                trailers = "Story: %s\nDocs-Commit: %s\nAcceptance: %s-AC01, %s-AC02" % (
                    STORY, self.docs_sha, STORY, STORY)
            message = "%s\n\n%s\n" % (body, trailers)
        git(self.platform, "commit", "-q", "-F", "-", stdin=message.encode())
        return git(self.platform, "rev-parse", "HEAD")

    def run_checker(self, *args, cwd=None):
        proc = subprocess.run([sys.executable, str(CHECKER), *args], cwd=cwd or self.platform,
                              capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout

    def check_commits(self, rng="main..story", cwd=None):
        return self.run_checker("commits", "--docs-repo", str(self.docs), "--range=" + rng,
                                "--repo", str(self.platform), cwd=cwd)

    def check_lock(self):
        return self.run_checker("lock", "--docs-repo", str(self.docs),
                                "--lock", str(self.platform / "docs-lock.json"))

    def assertCodes(self, result, codes, exit_code=1):
        code, out = result
        found = [line.split()[1] for line in out.splitlines() if line.startswith("ERROR ")]
        self.assertEqual(found, codes, out)
        self.assertEqual(code, exit_code, out)


class PositivePath(LinkageFixture):
    """M0-E02-S01-AC01."""

    def test_valid_lock_and_commits_pass_without_modifying_repositories(self):
        self.commit()
        self.commit(trailers="Story: %s\nDocs-Commit: %s\nAcceptance: %s-AC03\nCo-Authored-By: x <x@example.invalid>"
                    % (STORY, self.docs_sha, STORY))
        before = (snapshot(self.docs), snapshot(self.platform))
        self.assertCodes(self.check_lock(), [], exit_code=0)
        self.assertCodes(self.check_commits(), [], exit_code=0)
        self.assertEqual((snapshot(self.docs), snapshot(self.platform)), before)

    def test_lock_bump_does_not_invalidate_earlier_commits(self):
        self.commit()
        stories, acs = default_backlog()
        new_sha = self.make_docs(stories + [{"id": "M0-E02-S03", "status": "ready"}], acs)
        self.docs_sha = new_sha
        self.write_lock(new_sha)
        self.commit()
        self.assertCodes(self.check_commits(), [], exit_code=0)

    def test_merge_commits_are_checked_and_can_pass(self):
        self.commit()
        git(self.platform, "checkout", "-q", "-b", "side", "main")
        self.commit()
        git(self.platform, "checkout", "-q", "story")
        msg = "Merge side\n\nStory: %s\nDocs-Commit: %s\nAcceptance: %s-AC01\n" % (STORY, self.docs_sha, STORY)
        git(self.platform, "merge", "-q", "--no-ff", "-X", "theirs", "side", "-m", msg)
        self.assertCodes(self.check_commits(), [], exit_code=0)

    def test_status_in_progress_and_review_are_accepted(self):
        for status in ("in-progress", "review"):
            stories, acs = default_backlog()
            stories[0]["status"] = status
            self.docs_sha = self.make_docs(stories, acs)
            self.write_lock()
            self.commit()
            self.assertCodes(self.check_commits("HEAD~1..HEAD"), [], exit_code=0)


class NegativeCases(LinkageFixture):
    """M0-E02-S01-AC02: one case per error code."""

    def test_lock_missing(self):
        self.assertCodes(self.check_lock(), ["LOCK_MISSING"])
        self.commit(lock=False)
        self.assertCodes(self.check_commits(), ["LOCK_MISSING"])

    def test_lock_invalid_variants(self):
        variants = [
            "not json",
            json.dumps([1]),
            json.dumps({"schema": 1, "docs_repo": "cloud-product-docs"}),
            json.dumps({"schema": 1, "docs_repo": "cloud-product-docs", "commit": self.docs_sha, "x": 1}),
            json.dumps({"schema": 2, "docs_repo": "cloud-product-docs", "commit": self.docs_sha}),
            json.dumps({"schema": True, "docs_repo": "cloud-product-docs", "commit": self.docs_sha}),
            json.dumps({"schema": 1, "docs_repo": "other", "commit": self.docs_sha}),
        ]
        for raw in variants:
            with self.subTest(raw=raw):
                self.write_lock(raw=raw)
                self.assertCodes(self.check_lock(), ["LOCK_INVALID"])

    def test_sha_invalid_short_and_uppercase(self):
        for bad in (self.docs_sha[:12], self.docs_sha.upper(), 123):
            with self.subTest(bad=bad):
                self.write_lock(raw=json.dumps({"schema": 1, "docs_repo": "cloud-product-docs", "commit": bad}))
                self.assertCodes(self.check_lock(), ["SHA_INVALID"])

    def test_docs_commit_not_found(self):
        self.write_lock("0" * 40)
        self.assertCodes(self.check_lock(), ["DOCS_COMMIT_NOT_FOUND"])

    def test_trailer_missing(self):
        self.commit(trailers="Story: %s\nAcceptance: %s-AC01" % (STORY, STORY))
        self.assertCodes(self.check_commits(), ["TRAILER_MISSING"])

    def test_no_trailer_paragraph(self):
        self.commit(message="Just a subject\n")
        self.assertCodes(self.check_commits(), ["TRAILER_MISSING"] * 3)

    def test_trailers_not_in_final_paragraph_are_ignored(self):
        trailers = "Story: %s\nDocs-Commit: %s\nAcceptance: %s-AC01" % (STORY, self.docs_sha, STORY)
        self.commit(message="Subject\n\n%s\n\nTrailing prose line.\n" % trailers)
        self.assertCodes(self.check_commits(), ["TRAILER_MISSING"] * 3)

    def test_trailer_duplicate(self):
        self.commit(trailers="Story: %s\nStory: %s\nDocs-Commit: %s\nAcceptance: %s-AC01"
                    % (STORY, STORY, self.docs_sha, STORY))
        self.assertCodes(self.check_commits(), ["TRAILER_DUPLICATE"])

    def test_docs_commit_mismatch(self):
        stories, acs = default_backlog()
        other = self.make_docs(stories, acs)
        self.commit(trailers="Story: %s\nDocs-Commit: %s\nAcceptance: %s-AC01" % (STORY, other, STORY))
        self.assertCodes(self.check_commits(), ["DOCS_COMMIT_MISMATCH"])

    def test_story_unknown(self):
        self.commit(trailers="Story: M9-E99-S99\nDocs-Commit: %s\nAcceptance: %s-AC01" % (self.docs_sha, STORY))
        self.assertCodes(self.check_commits(), ["AC_WRONG_STORY", "STORY_UNKNOWN"])

    def test_story_not_ready(self):
        self.commit(trailers="Story: M0-E02-S02\nDocs-Commit: %s\nAcceptance: M0-E02-S02-AC01" % self.docs_sha)
        self.assertCodes(self.check_commits(), ["STORY_NOT_READY"])

    def test_ac_unknown(self):
        self.commit(trailers="Story: %s\nDocs-Commit: %s\nAcceptance: %s-AC09" % (STORY, self.docs_sha, STORY))
        self.assertCodes(self.check_commits(), ["AC_UNKNOWN"])

    def test_ac_wrong_story(self):
        self.commit(trailers="Story: %s\nDocs-Commit: %s\nAcceptance: M0-E02-S02-AC01" % (STORY, self.docs_sha))
        self.assertCodes(self.check_commits(), ["AC_WRONG_STORY"])

    def test_id_invalid(self):
        self.commit(trailers="Story: m0-e02-s01\nDocs-Commit: %s\nAcceptance: AC01" % self.docs_sha)
        self.assertCodes(self.check_commits(), ["ID_INVALID", "ID_INVALID"])

    def test_input_too_large_lock(self):
        self.write_lock(raw=" " * 5000 + "{}")
        self.assertCodes(self.check_lock(), ["INPUT_TOO_LARGE"])

    def test_input_too_large_message(self):
        self.commit(body="x" * 70000)
        self.assertCodes(self.check_commits(), ["INPUT_TOO_LARGE"])

    def test_backlog_invalid(self):
        sha = self.make_docs(None, [], raw_stories="{broken")
        self.write_lock(sha)
        self.assertCodes(self.check_lock(), ["BACKLOG_INVALID"])

    def test_backlog_wrong_types(self):
        sha = self.make_docs([{"id": STORY, "status": 3}], [])
        self.write_lock(sha)
        self.assertCodes(self.check_lock(), ["BACKLOG_INVALID"])

    def test_docs_repo_unavailable(self):
        code, out = self.run_checker("lock", "--docs-repo", str(self.root / "missing"))
        self.assertCodes((code, out), ["DOCS_REPO_UNAVAILABLE"], exit_code=2)
        plain = self.root / "plain"
        plain.mkdir()
        code, out = self.run_checker("lock", "--docs-repo", str(plain))
        self.assertCodes((code, out), ["DOCS_REPO_UNAVAILABLE"], exit_code=2)

    def test_range_invalid(self):
        for rng in ("main", "main...story", "main..nosuchbranch", "-x..story", "main..st$ory", "a..b..c"):
            with self.subTest(rng=rng):
                self.assertCodes(self.check_commits(rng), ["RANGE_INVALID"], exit_code=2)

    def test_usage_error_exits_2(self):
        code, _ = self.run_checker("commits")
        self.assertEqual(code, 2)
        code, _ = self.run_checker("bogus")
        self.assertEqual(code, 2)

    def test_git_failed_when_git_missing(self):
        env = {**os.environ, "PATH": str(self.root / "empty")}
        proc = subprocess.run([sys.executable, str(CHECKER), "lock", "--docs-repo", str(self.docs)],
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("ERROR GIT_FAILED", proc.stdout)

    def test_output_is_deterministic(self):
        self.commit(trailers="Story: m0\nDocs-Commit: abc\nAcceptance: x, y")
        first = self.check_commits()
        self.assertEqual(first, self.check_commits())
        self.assertCodes(first, ["ID_INVALID", "ID_INVALID", "ID_INVALID", "SHA_INVALID"])


class HostileInput(LinkageFixture):
    """M0-E02-S01-AC03."""

    def assertNoSideEffects(self, before, out):
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), before)
        for line in out.splitlines():
            self.assertLessEqual(len(line.split(": ", 1)[-1]), 200 + 120, line)

    def test_shell_metacharacters_and_option_values(self):
        before = sorted(p.name for p in self.root.iterdir())
        pwned = self.root / "pwned"
        hostile = ["$(touch %s)" % pwned, "`touch %s`" % pwned, "; touch %s" % pwned,
                   "--output=%s" % (self.root / "x"), "-n", "M0-E02-S01;id"]
        for value in hostile:
            with self.subTest(value=value):
                self.commit(trailers="Story: %s\nDocs-Commit: %s\nAcceptance: %s" % (value, value, value))
                code, out = self.check_commits("HEAD~1..HEAD")
                self.assertEqual(code, 1, out)
                codes = {line.split()[1] for line in out.splitlines()}
                self.assertEqual(codes, {"ID_INVALID", "SHA_INVALID"}, out)
                self.assertFalse(pwned.exists())
                self.assertNoSideEffects(before, out)

    def test_option_like_lock_commit(self):
        before = sorted(p.name for p in self.root.iterdir())
        self.write_lock(raw=json.dumps({"schema": 1, "docs_repo": "cloud-product-docs",
                                        "commit": "--output=%s" % (self.root / "x")}))
        self.assertCodes(self.check_lock(), ["SHA_INVALID"])
        self.assertFalse((self.root / "x").exists())
        self.assertNoSideEffects(before, "")

    def test_oversized_trailer_value(self):
        self.commit(trailers="Story: %s\nDocs-Commit: %s\nAcceptance: %s" % (STORY, self.docs_sha, "A" * 5000))
        self.assertCodes(self.check_commits(), ["INPUT_TOO_LARGE"])

    def test_echoed_untrusted_text_is_bounded_and_sanitized(self):
        self.commit(trailers="Story: %s\nDocs-Commit: %s\nAcceptance: %s"
                    % ("\x1b[31m" + "Z" * 900, self.docs_sha, STORY + "-AC01"))
        code, out = self.check_commits()
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", out)
        echoed = out.split("invalid story ID: ", 1)[1].splitlines()[0]
        self.assertLessEqual(len(echoed), 200)


class PinnedCommitOnly(LinkageFixture):
    """M0-E02-S01-AC04."""

    def test_dirty_or_switched_docs_working_tree_is_ignored(self):
        self.commit()
        expected = (self.check_lock(), self.check_commits())
        (self.docs / "backlog/stories.json").write_text(json.dumps([{"id": STORY, "status": "proposed"}]))
        (self.docs / "backlog/acceptance.json").write_text("garbage")
        self.assertEqual((self.check_lock(), self.check_commits()), expected)
        git(self.docs, "checkout", "-q", "-f", "-b", "other")
        git(self.docs, "rm", "-q", "-r", "backlog")
        git(self.docs, "commit", "-q", "-m", "remove backlog")
        self.assertEqual((self.check_lock(), self.check_commits()), expected)
        self.assertEqual(expected[0][0], 0)
        self.assertEqual(expected[1][0], 0)


class ReviewRegressions(LinkageFixture):
    """Regression tests for independent-review findings F1-F12."""

    def object_files(self, repo):
        return sorted(str(p) for p in (Path(repo) / ".git" / "objects").rglob("*") if p.is_file())

    def test_partial_clone_never_fetches_or_runs_remote_helper(self):
        # F1: lazy fetch through a hostile ext:: remote must not run or write.
        clone = self.root / "partial"
        git(self.docs, "config", "uploadpack.allowFilter", "true")
        subprocess.run(["git", "clone", "-q", "--no-checkout", "--filter=blob:none",
                        "file://%s" % self.docs, str(clone)], env=GIT_ENV, check=True, capture_output=True)
        pwned = self.root / "PWNED"
        git(clone, "config", "protocol.ext.allow", "always")
        git(clone, "config", "remote.origin.url", "ext::sh -c touch%% %s" % pwned)
        self.write_lock()
        before = self.object_files(clone)
        code, out = self.run_checker("lock", "--docs-repo", str(clone),
                                     "--lock", str(self.platform / "docs-lock.json"))
        self.assertFalse(pwned.exists())
        self.assertEqual(self.object_files(clone), before)
        self.assertCodes((code, out), ["BACKLOG_INVALID"])

    def test_inherited_git_dir_is_ignored(self):
        # F2: GIT_DIR in the caller environment must not redirect docs queries.
        fake = self.root / "fake"
        fake.mkdir()
        git(fake, "init", "-q", "-b", "main")
        (fake / "backlog").mkdir()
        stories, acs = default_backlog()
        (fake / "backlog/stories.json").write_text(json.dumps(stories))
        (fake / "backlog/acceptance.json").write_text(json.dumps(acs))
        git(fake, "add", "-A")
        git(fake, "commit", "-q", "-m", "fake")
        self.write_lock(git(fake, "rev-parse", "HEAD"))
        env = {**os.environ, "GIT_DIR": str(fake / ".git"), "GIT_OBJECT_DIRECTORY": str(fake / ".git/objects")}
        proc = subprocess.run([sys.executable, str(CHECKER), "lock", "--docs-repo", str(self.docs),
                               "--lock", str(self.platform / "docs-lock.json")],
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertCodes((proc.returncode, proc.stdout), ["DOCS_COMMIT_NOT_FOUND"])

    def test_directory_inside_a_repo_is_not_a_docs_repo(self):
        # F3: parent-directory discovery must not accept a subdirectory.
        sub = self.platform / "notarepo"
        sub.mkdir()
        self.write_lock()
        code, out = self.run_checker("lock", "--docs-repo", str(sub))
        self.assertCodes((code, out), ["DOCS_REPO_UNAVAILABLE"], exit_code=2)

    def test_replace_refs_are_ignored(self):
        # F4: git replace must not substitute the pinned commit's backlog.
        stories, acs = default_backlog()
        stories[0]["status"] = "proposed"
        pinned = self.make_docs(stories, acs)
        stories[0]["status"] = "ready"
        other = self.make_docs(stories, acs)
        git(self.docs, "replace", pinned, other)
        self.docs_sha = pinned
        self.write_lock(pinned)
        self.commit()
        self.assertCodes(self.check_commits(), ["STORY_NOT_READY"])

    def test_merge_without_trailers_fails(self):
        # F5: merge commits are checked.
        self.commit()
        git(self.platform, "checkout", "-q", "-b", "side", "main")
        self.commit()
        git(self.platform, "checkout", "-q", "story")
        git(self.platform, "merge", "-q", "--no-ff", "-X", "theirs", "side", "-m", "Merge side")
        merge = git(self.platform, "rev-parse", "HEAD")[:12]
        code, out = self.check_commits()
        self.assertCodes((code, out), ["TRAILER_MISSING"] * 3)
        self.assertTrue(all(merge in line for line in out.splitlines()), out)

    def orphan(self, subject):
        git(self.platform, "checkout", "-q", "--orphan", "orphan-%d" % len(subject))
        (self.platform / "o.txt").write_text(subject)
        git(self.platform, "add", "-A")
        git(self.platform, "commit", "-q", "-m", subject)
        return git(self.platform, "rev-parse", "HEAD")

    def test_baseline_exemption_requires_root_and_prefix(self):
        # F6/D-01: an unregistered orphan "Baseline:" commit is not exempt.
        root_ok = self.orphan("Baseline: other import")
        self.assertCodes(self.run_checker("commits", "--docs-repo", str(self.docs), "--range=main.." + root_ok,
                                          "--repo", str(self.platform)), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)
        root_bad = self.orphan("Initial import")
        self.assertCodes(self.run_checker("commits", "--docs-repo", str(self.docs), "--range=main.." + root_bad,
                                          "--repo", str(self.platform)), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)
        git(self.platform, "checkout", "-q", "story")
        self.commit(message="Baseline: not a root\n")
        self.assertCodes(self.check_commits(), ["TRAILER_MISSING"] * 3)

    def trailers_with(self, acceptance):
        return "Story: %s\nDocs-Commit: %s\nAcceptance: %s" % (STORY, self.docs_sha, acceptance)

    def test_trailer_size_boundary(self):
        # F7: 1024 bytes accepted (as far as size goes), 1025 rejected.
        item = "%s-AC01" % STORY
        ok = item + "," + " " * (1024 - 2 * len(item) - 1) + item
        self.assertEqual(len(ok), 1024)
        self.commit(trailers=self.trailers_with(ok))
        self.assertCodes(self.check_commits("HEAD~1..HEAD"), [], exit_code=0)
        self.commit(trailers=self.trailers_with("A" * 1025))
        self.assertCodes(self.check_commits("HEAD~1..HEAD"), ["INPUT_TOO_LARGE"])

    def test_message_size_boundary(self):
        trailers = self.trailers_with("%s-AC01" % STORY)
        fixed = len(("\n\n%s\n" % trailers).encode())
        self.commit(body="x" * (65536 - fixed), trailers=trailers)
        self.assertCodes(self.check_commits("HEAD~1..HEAD"), [], exit_code=0)
        self.commit(body="x" * (65537 - fixed), trailers=trailers)
        self.assertCodes(self.check_commits("HEAD~1..HEAD"), ["INPUT_TOO_LARGE"])

    def test_lock_size_boundary(self):
        base = json.dumps({"schema": 1, "docs_repo": "cloud-product-docs", "commit": self.docs_sha})
        self.write_lock(raw=base + " " * (4096 - len(base)))
        self.assertCodes(self.check_lock(), [], exit_code=0)
        self.write_lock(raw=base + " " * (4097 - len(base)))
        self.assertCodes(self.check_lock(), ["INPUT_TOO_LARGE"])
        self.commit()
        self.assertCodes(self.check_commits(), ["INPUT_TOO_LARGE"])

    def test_annotated_tag_is_not_a_commit(self):
        # F8: a tag object SHA must not pass as a docs commit.
        git(self.docs, "tag", "-a", "v1", "-m", "tag")
        self.write_lock(git(self.docs, "rev-parse", "v1"))
        self.assertCodes(self.check_lock(), ["DOCS_COMMIT_NOT_FOUND"])

    def test_unreadable_lock_is_a_finding(self):
        # F10: LOCK_MISSING is a finding (exit 1), also for a directory.
        (self.platform / "docs-lock.json").mkdir()
        self.assertCodes(self.check_lock(), ["LOCK_MISSING"])

    def test_lock_directory_in_commit_tree(self):
        (self.platform / "docs-lock.json").mkdir()
        (self.platform / "docs-lock.json" / "f").write_text("x")
        self.commit(lock=False)
        self.assertCodes(self.check_commits(), ["LOCK_INVALID"])

    def test_empty_then_valid_duplicate_is_duplicate(self):
        # F11
        self.commit(trailers="Story:\nStory: %s\nDocs-Commit: %s\nAcceptance: %s-AC01" % (STORY, self.docs_sha, STORY))
        self.assertCodes(self.check_commits(), ["TRAILER_DUPLICATE"])

    def test_newline_split_value_fails_closed(self):
        # F12: a value broken across lines makes the trailer block unparseable.
        self.commit(trailers="Story: M0-E02-\n$(touch %s)\nDocs-Commit: %s\nAcceptance: %s-AC01"
                    % (self.root / "pwned", self.docs_sha, STORY))
        self.assertCodes(self.check_commits(), ["TRAILER_MISSING"] * 3)
        self.assertFalse((self.root / "pwned").exists())

    def test_git_timeout_is_git_failed(self):
        bindir = self.root / "slowbin"
        bindir.mkdir()
        fake = bindir / "git"
        fake.write_text("#!/bin/sh\nexec %s 5\n" % shutil.which("sleep"))
        fake.chmod(0o755)
        spec = importlib.util.spec_from_file_location("check_linkage", CHECKER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.GIT_TIMEOUT_S = 0.5
        old_path = os.environ["PATH"]
        os.environ["PATH"] = str(bindir)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = module.main(["lock", "--docs-repo", str(self.docs)])
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(code, 2)
        self.assertIn("ERROR GIT_FAILED", buf.getvalue())



class ReReviewRegressions(LinkageFixture):
    """Regression tests for re-review findings N1-N5."""

    def fake_git(self, body):
        bindir = self.root / "fakebin"
        bindir.mkdir(exist_ok=True)
        fake = bindir / "git"
        fake.write_text("#!/bin/sh\n%s\n" % body)
        fake.chmod(0o755)
        return {**os.environ, "PATH": "%s:%s" % (bindir, os.environ["PATH"])}

    def test_old_git_fails_closed(self):
        # N1: git < 2.44 ignores lazy-fetch guards, so refuse to run.
        env = self.fake_git('for a in "$@"; do [ "$a" = version ] && { echo "git version 2.39.5"; exit 0; }; done\n'
                            'exec %s "$@"' % shutil.which("git"))
        self.write_lock()
        proc = subprocess.run([sys.executable, str(CHECKER), "lock", "--docs-repo", str(self.docs),
                               "--lock", str(self.platform / "docs-lock.json")],
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("ERROR GIT_FAILED git: git >= 2.44 required", proc.stdout)

    def test_lazy_fetch_option_is_passed_to_git(self):
        # N1: --no-lazy-fetch must be on every invocation (fails closed on old git).
        log = self.root / "argv.log"
        env = self.fake_git('printf "%%s\\n" "$*" >> %s\nexec %s "$@"' % (log, shutil.which("git")))
        self.commit()
        proc = subprocess.run([sys.executable, str(CHECKER), "commits", "--docs-repo", str(self.docs),
                               "--range=main..story", "--repo", str(self.platform)],
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        calls = log.read_text().splitlines()
        self.assertTrue(calls)
        for call in calls:
            self.assertTrue(call.startswith("--no-lazy-fetch --no-replace-objects "), call)
            for proto in ("ext", "file", "ssh", "git", "http", "https"):
                self.assertIn("protocol.%s.allow=never" % proto, call)

    def test_graft_file_cannot_hide_commits(self):
        # N2: .git/info/grafts must not truncate the checked range.
        self.commit(message="No trailers here\n")
        bad = git(self.platform, "rev-parse", "HEAD")
        self.commit()
        head = git(self.platform, "rev-parse", "HEAD")
        base = git(self.platform, "rev-parse", "main")
        (self.platform / ".git/info").mkdir(exist_ok=True)
        (self.platform / ".git/info/grafts").write_text("%s %s\n" % (head, base))
        code, out = self.check_commits()
        self.assertCodes((code, out), ["TRAILER_MISSING"] * 3)
        self.assertIn(bad[:12], out)

    def test_baseline_without_colon_is_not_exempt(self):
        # N4
        git(self.platform, "checkout", "-q", "--orphan", "nocolon")
        self.commit(message="Baseline import\n", lock=False)
        sha = git(self.platform, "rev-parse", "HEAD")
        self.assertCodes(self.run_checker("commits", "--docs-repo", str(self.docs), "--range=main.." + sha,
                                          "--repo", str(self.platform)), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)

    def test_docs_path_with_trailing_space(self):
        # N5: a valid repository whose directory name ends in a space.
        spaced = self.root / "docs "
        self.docs.rename(spaced)
        self.docs = spaced
        self.write_lock()
        self.assertCodes(self.check_lock(), [], exit_code=0)

    def test_fifo_lock_does_not_block(self):
        # N5: a FIFO lock path must not hang.
        fifo = self.root / "lock.fifo"
        os.mkfifo(fifo)
        code, out = self.run_checker("lock", "--docs-repo", str(self.docs), "--lock", str(fifo))
        self.assertCodes((code, out), ["LOCK_MISSING"])



class RegistryHelpers:
    """Fixture helpers for baseline-registry tests (mixin; defines no tests)."""

    def register(self, shas, raw=None):
        (self.docs / "backlog/baselines.json").write_text(
            raw if raw is not None else json.dumps({"schema": 1, "repos": {"cloud-platform": shas}}))
        git(self.docs, "add", "-A")
        git(self.docs, "commit", "-q", "-m", "register baselines")
        self.docs_sha = git(self.docs, "rev-parse", "HEAD")

    def orphan_then_child(self, subject, register=True, raw=None):
        """Orphan root commit, optionally registered, then a linked child commit."""
        git(self.platform, "checkout", "-q", "--orphan", "imported")
        git(self.platform, "rm", "-q", "-r", "--cached", ".")
        (self.platform / "imported.txt").write_text("imported\n")
        git(self.platform, "add", "imported.txt")
        git(self.platform, "commit", "-q", "-m", subject)
        root = git(self.platform, "rev-parse", "HEAD")
        self.register([root] if register else [], raw=raw)
        self.write_lock()
        self.commit()
        return root

    def check(self):
        return self.run_checker("commits", "--docs-repo", str(self.docs), "--range=main..imported",
                                "--repo", str(self.platform))


class BaselineRegistry(RegistryHelpers, LinkageFixture):
    """D-01: only baseline commits registered in the docs repo are exempt."""

    def test_registered_baseline_is_exempt(self):
        self.orphan_then_child("Baseline: documented import")
        self.assertCodes(self.check(), [], exit_code=0)

    def test_unregistered_orphan_baseline_is_not_exempt(self):
        root = self.orphan_then_child("Baseline: smuggled import", register=False)
        code, out = self.check()
        self.assertCodes((code, out), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)
        self.assertIn(root[:12], out)

    def test_registered_sha_still_needs_baseline_subject(self):
        self.orphan_then_child("Initial import")
        self.assertCodes(self.check(), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)

    def test_lookalike_of_registered_baseline_is_not_exempt(self):
        # Hostile history: same subject and content as a registered baseline, different SHA.
        real = self.orphan_then_child("Baseline: documented import")
        git(self.platform, "checkout", "-q", "--orphan", "lookalike")
        git(self.platform, "rm", "-q", "-r", "--cached", ".")
        git(self.platform, "clean", "-q", "-fdx")
        (self.platform / "imported.txt").write_text("imported\n")
        git(self.platform, "add", "imported.txt")
        env_date = {"GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
        subprocess.run(["git", "-C", str(self.platform), "commit", "-q", "-m", "Baseline: documented import"],
                       env={**GIT_ENV, **env_date}, check=True, capture_output=True)
        fake = git(self.platform, "rev-parse", "HEAD")
        self.assertNotEqual(fake, real)
        self.write_lock()
        self.commit()
        code, out = self.run_checker("commits", "--docs-repo", str(self.docs), "--range=main..lookalike",
                                     "--repo", str(self.platform))
        self.assertCodes((code, out), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)
        self.assertIn(fake[:12], out)

    def test_trailered_merge_cannot_smuggle_orphan(self):
        # F13: an orphan "Baseline:" commit merged into a story branch by a
        # correctly trailered merge is still checked.
        self.commit()
        git(self.platform, "checkout", "-q", "--orphan", "smuggle")
        git(self.platform, "rm", "-q", "-r", "--cached", ".")
        git(self.platform, "clean", "-q", "-fdx")
        (self.platform / "evil.sh").write_text("echo pwned\n")
        git(self.platform, "add", "evil.sh")
        git(self.platform, "commit", "-q", "-m", "Baseline: vendor drop")
        orphan = git(self.platform, "rev-parse", "HEAD")
        git(self.platform, "checkout", "-q", "-f", "story")
        msg = "Merge vendor\n\nStory: %s\nDocs-Commit: %s\nAcceptance: %s-AC01\n" % (STORY, self.docs_sha, STORY)
        git(self.platform, "merge", "-q", "--allow-unrelated-histories", "--no-ff", "smuggle", "-m", msg)
        code, out = self.check_commits()
        self.assertCodes((code, out), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)
        self.assertIn(orphan[:12], out)

    def test_malformed_registry_is_backlog_invalid(self):
        for raw in ("{broken", json.dumps({"schema": 1, "repos": {"cloud-platform": ["abc"]}}),
                    json.dumps({"schema": 2, "repos": {"cloud-platform": []}}),
                    json.dumps({"schema": 1, "repos": {}}), json.dumps([1])):
            with self.subTest(raw=raw):
                self.tearDown()
                self.setUp()
                self.orphan_then_child("Baseline: documented import", raw=raw)
                code, out = self.check()
                self.assertEqual(code, 1, out)
                self.assertIn("ERROR BACKLOG_INVALID", out)
                self.assertIn("TRAILER_MISSING", out)
                # I1: the head's registry finding comes after per-commit findings.
                self.assertTrue(out.strip().splitlines()[-1].startswith("ERROR BACKLOG_INVALID"), out)

    def test_missing_registry_exempts_nothing(self):
        self.orphan_then_child("Baseline: documented import", register=False)
        (self.docs / "backlog/baselines.json").unlink()
        git(self.docs, "commit", "-q", "-am", "drop registry")
        self.docs_sha = git(self.docs, "rev-parse", "HEAD")
        self.write_lock()
        self.commit()
        self.assertCodes(self.check(), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)

    def test_registry_read_from_head_lock_only(self):
        # A registry at a docs commit not pinned by the range head is ignored.
        root = self.orphan_then_child("Baseline: documented import")
        stories, acs = default_backlog()
        self.docs_sha = self.make_docs(stories, acs)
        (self.docs / "backlog/baselines.json").write_text(json.dumps({"schema": 1, "repos": {"cloud-platform": []}}))
        git(self.docs, "commit", "-q", "-am", "unregister")
        self.docs_sha = git(self.docs, "rev-parse", "HEAD")
        self.write_lock()
        self.commit()
        code, out = self.check()
        self.assertCodes((code, out), ["LOCK_MISSING"] + ["TRAILER_MISSING"] * 3)
        self.assertIn(root[:12], out)



class ReviewCycle2Regressions(RegistryHelpers, LinkageFixture):
    """Regression tests for S01 review findings R1-R6 (this run)."""

    def test_shallow_platform_repo_refused(self):
        # R1: shallow boundaries would hide commits from the range.
        self.commit(message="No trailers\n")
        self.commit()
        head = git(self.platform, "rev-parse", "HEAD")
        (self.platform / ".git/shallow").write_text(head + "\n")
        self.assertCodes(self.check_commits(), ["GIT_FAILED"], exit_code=2)

    def test_shallow_clone_refused(self):
        self.commit(message="No trailers\n")
        self.commit()
        clone = self.root / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", "story", "file://%s" % self.platform,
                        str(clone)], env=GIT_ENV, check=True, capture_output=True)
        code, out = self.run_checker("commits", "--docs-repo", str(self.docs), "--range=HEAD~1..HEAD",
                                     "--repo", str(clone))
        self.assertEqual(code, 2, out)

    def test_shallow_docs_repo_refused(self):
        stories, acs = default_backlog()
        self.make_docs(stories, acs)
        clone = self.root / "docs-shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", "file://%s" % self.docs, str(clone)],
                       env=GIT_ENV, check=True, capture_output=True)
        self.write_lock(git(clone, "rev-parse", "HEAD"))
        code, out = self.run_checker("lock", "--docs-repo", str(clone), "--lock", str(self.platform / "docs-lock.json"))
        self.assertCodes((code, out), ["GIT_FAILED"], exit_code=2)

    def dangling_docs_commit(self, stories, acs, registry=None):
        """Commit on a throwaway docs branch, then delete the branch (dangling commit)."""
        git(self.docs, "checkout", "-q", "-b", "throwaway")
        sha = self.make_docs(stories, acs)
        if registry is not None:
            (self.docs / "backlog/baselines.json").write_text(json.dumps(registry))
            git(self.docs, "add", "-A")
            git(self.docs, "commit", "-q", "-m", "forged registry")
            sha = git(self.docs, "rev-parse", "HEAD")
        git(self.docs, "checkout", "-q", "-f", "main")
        git(self.docs, "branch", "-q", "-D", "throwaway")
        return sha

    def test_untrusted_docs_commit_cannot_forge_story_status(self):
        # R3: a docs commit not on trusted main cannot mark a story ready.
        stories, acs = default_backlog()
        stories[1]["status"] = "ready"
        forged = self.dangling_docs_commit(stories, acs)
        self.docs_sha = forged
        self.write_lock(forged)
        self.assertCodes(self.check_lock(), ["DOCS_COMMIT_UNTRUSTED"])
        self.commit(trailers="Story: M0-E02-S02\nDocs-Commit: %s\nAcceptance: M0-E02-S02-AC01" % forged)
        self.assertCodes(self.check_commits(), ["DOCS_COMMIT_UNTRUSTED"])

    def test_untrusted_docs_commit_cannot_register_baseline(self):
        # R3: the reviewer's dangling-registry bypass now fails.
        self.commit()
        git(self.platform, "checkout", "-q", "--orphan", "smuggle")
        git(self.platform, "rm", "-q", "-r", "--cached", ".")
        git(self.platform, "clean", "-q", "-fdx")
        (self.platform / "evil.sh").write_text("echo pwned\n")
        git(self.platform, "add", "evil.sh")
        git(self.platform, "commit", "-q", "-m", "Baseline: vendor drop")
        orphan = git(self.platform, "rev-parse", "HEAD")
        stories, acs = default_backlog()
        forged = self.dangling_docs_commit(stories, acs, {"schema": 1, "repos": {"cloud-platform": [orphan]}})
        git(self.platform, "checkout", "-q", "-f", "story")
        self.docs_sha = forged
        self.write_lock(forged)
        self.commit()
        msg = "Merge vendor\n\nStory: %s\nDocs-Commit: %s\nAcceptance: %s-AC01\n" % (STORY, forged, STORY)
        git(self.platform, "merge", "-q", "--allow-unrelated-histories", "--no-ff", "smuggle", "-m", msg)
        code, out = self.check_commits()
        self.assertEqual(code, 1, out)
        self.assertIn("TRAILER_MISSING %s" % orphan[:12], out)
        self.assertIn("DOCS_COMMIT_UNTRUSTED", out)

    def test_custom_and_missing_trusted_docs_ref(self):
        stories, acs = default_backlog()
        git(self.docs, "branch", "-q", "release")
        self.write_lock()
        code, out = self.run_checker("lock", "--docs-repo", str(self.docs), "--docs-ref", "refs/heads/release",
                                     "--lock", str(self.platform / "docs-lock.json"))
        self.assertCodes((code, out), [], exit_code=0)
        code, out = self.run_checker("lock", "--docs-repo", str(self.docs), "--docs-ref", "refs/heads/nope",
                                     "--lock", str(self.platform / "docs-lock.json"))
        self.assertCodes((code, out), ["DOCS_REPO_UNAVAILABLE"], exit_code=2)
        code, out = self.run_checker("lock", "--docs-repo", str(self.docs), "--docs-ref=--output=/tmp/x",
                                     "--lock", str(self.platform / "docs-lock.json"))
        self.assertCodes((code, out), ["DOCS_REPO_UNAVAILABLE"], exit_code=2)

    def test_allow_protocol_env_is_none(self):
        # R4: GIT_ALLOW_PROTOCOL=none overrides custom remote helpers.
        log = self.root / "env.log"
        bindir = self.root / "envbin"
        bindir.mkdir()
        fake = bindir / "git"
        fake.write_text('#!/bin/sh\necho "$GIT_ALLOW_PROTOCOL" >> %s\nexec %s "$@"\n' % (log, shutil.which("git")))
        fake.chmod(0o755)
        self.write_lock()
        proc = subprocess.run([sys.executable, str(CHECKER), "lock", "--docs-repo", str(self.docs),
                               "--lock", str(self.platform / "docs-lock.json")], capture_output=True, text=True,
                              env={**os.environ, "PATH": "%s:%s" % (bindir, os.environ["PATH"]),
                                   "GIT_ALLOW_PROTOCOL": "ext:file"}, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual(set(log.read_text().split()), {"none"})

    def test_deeply_nested_backlog_is_typed(self):
        # R5
        sha = self.make_docs(None, [], raw_stories="[" * 100000 + "]" * 100000)
        self.write_lock(sha)
        code, out = self.check_lock()
        self.assertCodes((code, out), ["BACKLOG_INVALID"])
        self.assertNotIn("Traceback", out)

    def test_registered_sha_with_parents_is_not_exempt(self):
        # R6: registry membership never exempts a commit that has parents.
        self.commit(message="Baseline: has a parent\n")
        child = git(self.platform, "rev-parse", "HEAD")
        self.register([child])
        self.write_lock()
        self.commit()
        code, out = self.check_commits()
        self.assertIn("TRAILER_MISSING %s" % child[:12], out)

    def test_registry_prefix_match_is_not_exempt(self):
        # R6: exact 40-hex match only; a different SHA sharing a 12-char prefix does not count.
        root = self.orphan_then_child("Baseline: documented import", register=False)
        lookalike = root[:12] + ("0" if root[12] != "0" else "1") + root[13:]
        self.register([lookalike])
        self.write_lock()
        self.commit()
        code, out = self.check()
        self.assertIn("TRAILER_MISSING %s" % root[:12], out)

    def test_registry_schema_strictness(self):
        for raw in (json.dumps({"schema": True, "repos": {"cloud-platform": []}}),
                    json.dumps({"schema": 1, "repos": {"cloud-platform": []}, "extra": 1}),
                    json.dumps({"schema": 1, "repos": {"cloud-platform": []}}) + " " * 5000):
            with self.subTest(raw=raw[:60]):
                self.tearDown()
                self.setUp()
                self.orphan_then_child("Baseline: documented import", raw=raw)
                self.assertIn("ERROR BACKLOG_INVALID", self.check()[1])

    def test_git_version_boundary(self):
        for version, ok in (("2.44.0", True), ("2.44.0.windows.1", True), ("2.43.9", False), ("3.0.0", True)):
            with self.subTest(version=version):
                bindir = self.root / ("v" + version)
                bindir.mkdir()
                fake = bindir / "git"
                fake.write_text('#!/bin/sh\nfor a in "$@"; do [ "$a" = version ] && { echo "git version %s"; exit 0; }; done\n'
                                'exec %s "$@"\n' % (version, shutil.which("git")))
                fake.chmod(0o755)
                self.write_lock()
                proc = subprocess.run([sys.executable, str(CHECKER), "lock", "--docs-repo", str(self.docs),
                                       "--lock", str(self.platform / "docs-lock.json")], capture_output=True,
                                      text=True, env={**os.environ, "PATH": "%s:%s" % (bindir, os.environ["PATH"])},
                                      timeout=60)
                self.assertEqual(proc.returncode, 0 if ok else 2, proc.stdout)


if __name__ == "__main__":
    unittest.main()

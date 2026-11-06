"""Integration tests for diffsec.

Each test builds a throwaway git repo with a known shape -- a patched site, an
unpatched sibling with no gate, and an unpatched sibling whose only negative
control is written in camelCase -- then runs ``analyze`` against it and asserts
the triage. The camelCase case is a regression guard: it is exactly the class
of silent miss (like the earlier case-sensitivity bug) that makes an agent
trust a false ``intent_test_hits: none``.

Run from the repo root:  python3 -m unittest test_diffsec
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import diffsec


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _write(repo: Path, rel: str, content: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _build_fixture(repo: Path) -> None:
    """A stable->fixed history with one patched site and two siblings."""
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "diffsec-test")
    _git(repo, "config", "commit.gpgsign", "false")

    # stable: sign-in writes a session cookie with no gate; two sibling plugins
    # do the same. email-otp has a test whose only mention of the gate is the
    # camelCase symbol, never the hyphenated directory name.
    _write(repo, "src/auth/sign-in.js", "export function signIn(s){ writeCookie(s); }\n")
    _write(repo, "src/plugins/magic-link/index.js", "export function ml(s){ writeCookie(s); }\n")
    _write(repo, "src/plugins/email-otp/index.js", "export function eo(s){ writeCookie(s); }\n")
    _write(
        repo,
        "src/plugins/email-otp/index.test.js",
        "// emailOtp intentionally skips applyGate: passwordless is its own factor\n",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial")
    _git(repo, "tag", "stable")

    # fixed: the gate is added to the sign-in site only (the patched site).
    _write(
        repo,
        "src/auth/sign-in.js",
        "export function signIn(s){ applyGate(s); writeCookie(s); }\n",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fix: harden auth cookie gate")
    _git(repo, "tag", "fixed")


PATTERN = {
    "name": "cookie-write",
    "regex": "writeCookie",
    "scope": ["src/**/*.js"],
    "exclude": ["**/*.test.js"],
    "intent_probe": "applyGate",
}


class DiffsecIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        _build_fixture(self.repo)
        self.report = diffsec.analyze(
            diffsec.GitRepo(self.repo),
            from_ref="stable",
            to_ref="fixed",
            scope=["src/**/*.js"],
            exclude=["**/*.test.js"],
            patterns=[PATTERN],
            min_score=2,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _siblings(self) -> dict[str, diffsec.Sibling]:
        return {s.file: s for s in self.report.patterns[0].unpatched_siblings}

    def test_schema_version_present(self) -> None:
        self.assertEqual(self.report.schema_version, "1")

    def test_security_commit_detected(self) -> None:
        harden = [c for c in self.report.security_commits if "harden" in c.subject]
        self.assertTrue(harden, "the 'harden' fix commit should be ranked")
        self.assertIn("src/auth/sign-in.js", harden[0].files)

    def test_patched_site_is_touched_not_sibling(self) -> None:
        pattern = self.report.patterns[0]
        self.assertIn("src/auth/sign-in.js", pattern.touched_files)
        self.assertNotIn("src/auth/sign-in.js", self._siblings())

    def test_ungated_sibling_flagged_with_no_control(self) -> None:
        ml = self._siblings().get("src/plugins/magic-link/index.js")
        self.assertIsNotNone(ml, "magic-link should be an unpatched sibling")
        self.assertFalse(ml.references_fix_mechanism)
        self.assertEqual(ml.intent_test_hits, [])

    def test_camelcase_negative_control_is_detected(self) -> None:
        # Regression guard: the only gate mention for email-otp is `emailOtp`
        # (camelCase), never the hyphenated dir name. Without camelCase variant
        # matching this comes back empty and the sibling looks like a top
        # unpatched candidate when it is actually intended.
        eo = self._siblings().get("src/plugins/email-otp/index.js")
        self.assertIsNotNone(eo, "email-otp should be an unpatched sibling")
        self.assertTrue(
            eo.intent_test_hits,
            "camelCase negative control must be detected",
        )
        self.assertTrue(
            any("index.test.js" in h.file for h in eo.intent_test_hits),
            "the hit should point at the test file",
        )


if __name__ == "__main__":
    unittest.main()

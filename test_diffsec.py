"""Integration tests for diffsec.

Each test builds a throwaway git repo with a known shape -- a patched site and
three unpatched siblings -- then runs ``analyze`` and asserts the triage. Two
cases are precision regression guards:

- a plugin-registration line (``emailOtpClient()`` beside ``applyGateClient()``)
  must NOT be credited as a negative control; and
- a behavioral control that names the module by its hyphenated directory name
  MUST be detected.

Run from the repo root:  python3 -m unittest test_diffsec
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import diffsec


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _write(repo: Path, rel: str, content: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _build_fixture(repo: Path) -> None:
    """A stable->fixed history with one patched site and three siblings."""
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "diffsec-test")
    _git(repo, "config", "commit.gpgsign", "false")

    # stable: the sign-in site and three plugins all write a session cookie with
    # no gate.
    _write(repo, "src/auth/sign-in.js", "export function signIn(s){ writeCookie(s); }\n")
    _write(repo, "src/plugins/magic-link/index.js", "export function ml(s){ writeCookie(s); }\n")
    _write(repo, "src/plugins/email-otp/index.js", "export function eo(s){ writeCookie(s); }\n")
    _write(repo, "src/plugins/sms-otp/index.js", "export function so(s){ writeCookie(s); }\n")
    _write(repo, "src/plugins/sso/index.js", "export function sso(s){ writeCookie(s); }\n")

    # email-otp's only co-mention of the gate is a plugin-REGISTRATION line in
    # camelCase. This must NOT count as a negative control.
    _write(
        repo,
        "src/plugins/email-otp/index.test.js",
        "const auth = setup({ plugins: [emailOtpClient(), applyGateClient()] });\n",
    )
    # sms-otp has a genuine BEHAVIORAL control that names the module by its
    # hyphenated directory name. This MUST be detected.
    _write(
        repo,
        "src/plugins/sms-otp/index.test.js",
        "// sms-otp sign-in intentionally skips applyGate: it is its own factor\n",
    )
    # sso's token ("sso") appears only as a substring of ssoClient() on a
    # registration line; whole-identifier matching must reject it.
    _write(
        repo,
        "src/plugins/sso/index.test.js",
        "const auth = setup({ plugins: [ssoClient(), applyGateClient()] });\n",
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

    def test_registration_line_not_credited(self) -> None:
        # Precision guard: email-otp's only gate co-mention is a camelCase
        # plugin-registration line. It must not be read as a negative control,
        # or a consumer would wrongly downgrade an uncontrolled sibling.
        eo = self._siblings().get("src/plugins/email-otp/index.js")
        self.assertIsNotNone(eo, "email-otp should be an unpatched sibling")
        self.assertEqual(
            eo.intent_test_hits, [],
            "a plugin-registration line must not count as a control",
        )

    def test_short_token_substring_not_credited(self) -> None:
        # Precision guard: "sso" appears only inside ssoClient() on a
        # registration line. Whole-identifier matching must not credit it.
        sso = self._siblings().get("src/plugins/sso/index.js")
        self.assertIsNotNone(sso, "sso should be an unpatched sibling")
        self.assertEqual(sso.intent_test_hits, [])

    def test_hyphen_named_control_is_detected(self) -> None:
        # Recall guard: a behavioral control naming the module by its hyphenated
        # directory name must still be detected.
        so = self._siblings().get("src/plugins/sms-otp/index.js")
        self.assertIsNotNone(so, "sms-otp should be an unpatched sibling")
        self.assertTrue(so.intent_test_hits, "hyphen-named control must be detected")
        self.assertTrue(
            any("index.test.js" in h.file for h in so.intent_test_hits),
            "the hit should point at the test file",
        )


if __name__ == "__main__":
    unittest.main()

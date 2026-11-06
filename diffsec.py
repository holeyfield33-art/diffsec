#!/usr/bin/env python3
"""
diffsec - differential security reconnaissance over a git repo.

Core idea (the hard-won lesson this tool exists to encode):

    Diffing a stable ref against a patched ref can only ever rediscover bugs
    the maintainer has ALREADY fixed. The patched ref *is* the patch. Every
    security delta you find in it is known-to-maintainer and fix-in-flight:
    zero novelty, and writing up the pre-patch exploit risks dropping a live
    0-day ahead of the maintainer's own release.

    So the diff is not the product. The product is: use each fix as a teacher
    of a BUG PATTERN, then find where that same pattern lives in code the patch
    did NOT touch (unpatched siblings). Those are the only novel-capable leads,
    and because they are still live they can be confirmed without pre-disclosing
    anything.

This tool does the mechanical half of that method and leaves judgement to the
caller (a human or an agent). It never decides a vulnerability exists. It
produces a grounded evidence bundle:

  1. Security-signal commits between two refs (ranked, not binary).
  2. Companion test files each such commit added/changed (these document the
     maintainer's intent for the fix).
  3. For each caller-supplied PATTERN: the full call-site surface at the
     patched ref, split into sites the patch touched vs. untouched siblings.
  4. A negative-control hint per sibling: whether the sibling references the
     fix mechanism, and which test files mention it. (Evidence, not a verdict.)

The tool is deliberately domain-agnostic. It knows nothing about auth, 2FA, or
any specific project. Patterns are input.

Python 3.9+, standard library only. No network. Never mutates the working tree.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Record / unit separators: safe delimiters for git log formatting, since
# commit bodies contain newlines but never these control bytes.
_US = "\x1f"  # between fields
_RS = "\x1e"  # between commits

# Security-signal vocabulary. Weighted, case-insensitive, matched on the commit
# subject + body. High-weight terms name an actual security property; mid-weight
# terms are auth-adjacent and only corroborate. This is a ranking input, never a
# gate on its own -- a careful maintainer often hides a real fix behind a dull
# "refactor" subject, so a zero score means "deprioritize", not "ignore".
_SIGNALS: dict[str, int] = {
    r"\bCVE-\d": 5,
    r"\bGHSA-": 5,
    r"\badvisor(y|ies)\b": 4,
    r"\bvulnerab": 4,
    r"\bexploit": 4,
    r"\bbypass": 4,
    r"\btakeover\b": 4,
    r"\bhijack": 4,
    r"\bescalat": 4,
    r"\bunauthori[sz]ed\b": 3,
    r"\bleak": 3,
    r"\bcsrf\b": 3,
    r"\bssrf\b": 3,
    r"\binjection\b": 3,
    r"\bspoof": 3,
    r"\breplay\b": 3,
    r"\btenant\b": 3,
    r"\bisolation\b": 3,
    r"\bharden": 3,
    r"\bsecurity\b": 3,
    r"\bauth(enticat|ori)": 2,
    r"\bsession\b": 2,
    r"\btoken\b": 2,
    r"\bcookie\b": 2,
    r"\bpermission": 2,
    r"\bcredential": 2,
    r"\bverif(y|ied|ication)\b": 1,
}

# Subject prefixes that conventional-commit projects use to flag a breaking
# change; a breaking security fix is the single strongest "they changed a real
# invariant" tell in practice.
_BREAKING = re.compile(r"(^|\s)\w+!:|\bBREAKING\b")

_TEST_FILE = re.compile(r"\.(test|spec)\.[tj]sx?$|(^|/)(tests?|__tests__)/")


class GitError(RuntimeError):
    pass


@dataclass
class Commit:
    sha: str
    subject: str
    body: str
    signal_score: int
    signals: list[str]
    breaking: bool
    files: list[str]
    companion_tests: list[str]


@dataclass
class SurfaceHit:
    file: str
    line: int
    snippet: str


@dataclass
class Sibling:
    file: str
    line: int
    snippet: str
    references_fix_mechanism: bool  # does the sibling file mention the fix mechanism at all?
    intent_test_hits: list[SurfaceHit]  # test lines that mention this module + the intent probe


@dataclass
class PatternResult:
    name: str
    regex: str
    surface_count: int
    touched_files: list[str]
    unpatched_siblings: list[Sibling]
    note: str = ""


@dataclass
class Report:
    repo: str
    from_ref: str
    to_ref: str
    grep_backend: str
    meta_warning: str
    security_commits: list[Commit]
    patterns: list[PatternResult] = field(default_factory=list)


class GitRepo:
    def __init__(self, path: Path):
        self.path = path
        if not (path / ".git").exists() and not (path / "HEAD").exists():
            raise GitError(f"{path} is not a git repository (no .git found)")

    def _run(self, args: list[str], allow_empty_fail: bool = False) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.path,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            # git grep exits 1 with no output when there are simply no matches;
            # that is a legitimate empty result, not an error.
            if allow_empty_fail and proc.returncode == 1 and not proc.stdout:
                return ""
            raise GitError(
                f"git {' '.join(args)} failed (exit {proc.returncode}):\n"
                f"{proc.stderr.strip()}"
            )
        return proc.stdout

    def verify_ref(self, ref: str) -> None:
        self._run(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])

    def _pathspecs(self, scope: list[str], exclude: list[str]) -> list[str]:
        specs = [f":(glob){g}" for g in scope] if scope else []
        specs += [f":(exclude,glob){g}" for g in exclude]
        return specs

    def security_commits(
        self, from_ref: str, to_ref: str, scope: list[str], exclude: list[str],
        min_score: int,
    ) -> list[Commit]:
        fmt = _US.join(["%H", "%s", "%b"]) + _RS
        specs = self._pathspecs(scope, exclude)
        out = self._run(
            ["log", f"--format={fmt}", f"{from_ref}..{to_ref}", "--", *specs]
        )
        commits: list[Commit] = []
        for raw in out.split(_RS):
            raw = raw.strip("\n")
            if not raw:
                continue
            parts = raw.split(_US)
            if len(parts) < 3:
                parts += [""] * (3 - len(parts))
            sha, subject, body = parts[0], parts[1], parts[2]
            haystack = f"{subject}\n{body}"
            matched: list[str] = []
            score = 0
            for pat, weight in _SIGNALS.items():
                if re.search(pat, haystack, re.IGNORECASE):
                    matched.append(pat.strip("\\b"))
                    score += weight
            breaking = bool(_BREAKING.search(subject))
            if breaking:
                score += 3
            if score < min_score:
                continue
            files, tests = self._commit_files(sha, specs)
            commits.append(
                Commit(
                    sha=sha[:9],
                    subject=subject,
                    body=body.strip(),
                    signal_score=score,
                    signals=sorted(set(matched)),
                    breaking=breaking,
                    files=files,
                    companion_tests=tests,
                )
            )
        commits.sort(key=lambda c: c.signal_score, reverse=True)
        return commits

    def _commit_files(self, sha: str, specs: list[str]) -> tuple[list[str], list[str]]:
        out = self._run(
            ["show", "--name-only", "--format=", sha, "--", *specs]
        )
        files = [ln.strip() for ln in out.splitlines() if ln.strip()]
        tests = [f for f in files if _TEST_FILE.search(f)]
        return files, tests

    def changed_files(
        self, from_ref: str, to_ref: str, scope: list[str], exclude: list[str]
    ) -> set[str]:
        specs = self._pathspecs(scope, exclude)
        out = self._run(["diff", "--name-only", from_ref, to_ref, "--", *specs])
        return {ln.strip() for ln in out.splitlines() if ln.strip()}

    def grep_ref(
        self, ref: str, regex: str, scope: list[str], exclude: list[str]
    ) -> list[SurfaceHit]:
        """Search a tree-ish for a regex WITHOUT checking it out.

        git grep against a ref reads blobs directly, so the working tree is
        never touched -- the tool is safe to run on a dirty checkout and leaves
        no mess. Output format is `ref:path:line:content`.
        """
        specs = self._pathspecs(scope, exclude)
        # -i: git grep is case-sensitive by default, but signal/intent terms are
        # routinely written in prose caps ("2FA", "CSRF", "TODO"). Matching
        # case-insensitively keeps grep consistent with the Python-side signal
        # scan; without it, negative controls written in caps go invisible and
        # intended-behaviour siblings get mislabelled as top candidates.
        out = self._run(
            ["grep", "-n", "-I", "-i", "-E", "-e", regex, ref, "--", *specs],
            allow_empty_fail=True,
        )
        hits: list[SurfaceHit] = []
        prefix = f"{ref}:"
        for ln in out.splitlines():
            if not ln.startswith(prefix):
                continue
            rest = ln[len(prefix):]
            # rest = path:line:content
            try:
                path, lineno, content = rest.split(":", 2)
            except ValueError:
                continue
            hits.append(
                SurfaceHit(file=path, line=int(lineno), snippet=content.strip())
            )
        return hits

    def file_mentions(self, ref: str, path: str, regex: str) -> bool:
        out = self._run(
            ["grep", "-c", "-I", "-i", "-E", "-e", regex, ref, "--", f":(glob){path}"],
            allow_empty_fail=True,
        )
        return bool(out.strip())


def _module_token(path: str) -> str:
    """A grep-safe token identifying a file's module, for intent probing.

    e.g. .../plugins/magic-link/index.ts -> "magic-link". Falls back to the
    file stem. Kept deliberately simple and generic.
    """
    parts = Path(path).parts
    stem = Path(path).stem
    if stem in ("index", "routes", "route") and len(parts) >= 2:
        return parts[-2]
    return stem


def analyze(
    repo: GitRepo,
    from_ref: str,
    to_ref: str,
    scope: list[str],
    exclude: list[str],
    patterns: list[dict],
    min_score: int,
) -> Report:
    repo.verify_ref(from_ref)
    repo.verify_ref(to_ref)

    commits = repo.security_commits(from_ref, to_ref, scope, exclude, min_score)
    changed = repo.changed_files(from_ref, to_ref, scope, exclude)

    results: list[PatternResult] = []
    for spec in patterns:
        name = spec["name"]
        regex = spec["regex"]
        p_scope = spec.get("scope", scope)
        p_exclude = spec.get("exclude", exclude)
        intent = spec.get("intent_probe")

        surface = repo.grep_ref(to_ref, regex, p_scope, p_exclude)
        touched = sorted({h.file for h in surface if h.file in changed})

        siblings: list[Sibling] = []
        seen_files: set[str] = set()
        for hit in surface:
            if hit.file in changed:
                continue  # touched by the patch -> already-handled ground
            if hit.file in seen_files:
                # one sibling entry per file is enough for triage; keep first hit
                continue
            seen_files.add(hit.file)

            references_fix = False
            intent_hits: list[SurfaceHit] = []
            if intent:
                references_fix = repo.file_mentions(to_ref, hit.file, intent)
                token = re.escape(_module_token(hit.file))
                # find test lines that mention this module AND the fix mechanism
                probe = f"({token}).*({intent})|({intent}).*({token})"
                test_hits = repo.grep_ref(
                    to_ref, probe,
                    scope=p_scope,
                    exclude=[g for g in p_exclude if not _TEST_FILE.search(g)] or [],
                )
                intent_hits = [h for h in test_hits if _TEST_FILE.search(h.file)][:5]

            siblings.append(
                Sibling(
                    file=hit.file,
                    line=hit.line,
                    snippet=hit.snippet,
                    references_fix_mechanism=references_fix,
                    intent_test_hits=intent_hits,
                )
            )

        note = ""
        if intent:
            note = (
                "A sibling with references_fix_mechanism=false AND no "
                "intent_test_hits is the strongest unpatched-candidate. A "
                "sibling with intent_test_hits likely has a negative control "
                "(intended behaviour) -- read those test lines before claiming "
                "anything."
            )
        results.append(
            PatternResult(
                name=name,
                regex=regex,
                surface_count=len({h.file for h in surface}),
                touched_files=touched,
                unpatched_siblings=siblings,
                note=note,
            )
        )

    meta = (
        "Everything in the from..to diff is a fix the maintainer already made: "
        "known, fix-in-flight, zero bounty novelty, and unsafe to write up as a "
        "pre-patch exploit. Do NOT treat the security_commits list as findings. "
        "The only novel-capable leads are unpatched_siblings -- pattern "
        "call-sites the patch did not touch -- and even those are hypotheses "
        "until a negative control is checked."
    )

    return Report(
        repo=str(repo.path),
        from_ref=from_ref,
        to_ref=to_ref,
        grep_backend="git grep",
        meta_warning=meta,
        security_commits=commits,
        patterns=results,
    )


def render_markdown(r: Report) -> str:
    out: list[str] = []
    w = out.append
    w(f"# diffsec report: {Path(r.repo).name}")
    w("")
    w(f"`{r.from_ref}` -> `{r.to_ref}`")
    w("")
    w("> **Read this first.** " + r.meta_warning)
    w("")

    if r.patterns:
        w("## Unpatched siblings (the only novel-capable leads)")
        w("")
        for p in r.patterns:
            w(f"### pattern `{p.name}`  (`/{p.regex}/`)")
            w("")
            w(f"- surface: {p.surface_count} file(s) match the pattern at `{r.to_ref}`")
            w(f"- patched by this diff: {len(p.touched_files)} file(s)")
            w(f"- **unpatched siblings: {len(p.unpatched_siblings)} file(s)**")
            if p.touched_files:
                w("")
                w("  patched (already-handled ground):")
                for f in p.touched_files:
                    w(f"  - `{f}`")
            w("")
            if not p.unpatched_siblings:
                w("  _No unpatched siblings: the fix covers the whole surface._")
                w("")
                continue
            w("  | sibling | refs fix mechanism? | negative-control test hits |")
            w("  |---|---|---|")
            for s in p.unpatched_siblings:
                nc = (
                    f"{len(s.intent_test_hits)} ("
                    + ", ".join(f"{h.file.split('/')[-1]}:{h.line}" for h in s.intent_test_hits)
                    + ")"
                    if s.intent_test_hits
                    else "none"
                )
                flag = "yes" if s.references_fix_mechanism else "**no**"
                w(f"  | `{s.file}:{s.line}` | {flag} | {nc} |")
            w("")
            if p.note:
                w(f"  _{p.note}_")
            w("")

    w("## Security-signal commits (context only -- NOT findings)")
    w("")
    if not r.security_commits:
        w("_None above threshold._")
    for c in r.security_commits:
        brk = " [BREAKING]" if c.breaking else ""
        w(f"### `{c.sha}` score {c.signal_score}{brk}")
        w(f"{c.subject}")
        w("")
        w(f"- signals: {', '.join(c.signals) or 'none (dull subject -- inspect anyway)'}")
        if c.companion_tests:
            w("- companion tests (document fix intent):")
            for t in c.companion_tests:
                w(f"  - `{t}`")
        w(f"- files touched: {len(c.files)}")
        w("")
    return "\n".join(out)


def load_patterns(args: argparse.Namespace) -> list[dict]:
    patterns: list[dict] = []
    if args.patterns:
        data = json.loads(Path(args.patterns).read_text())
        patterns.extend(data.get("patterns", data if isinstance(data, list) else []))
    for raw in args.pattern or []:
        if "=" not in raw:
            raise SystemExit(f"--pattern expects name=regex, got: {raw}")
        name, regex = raw.split("=", 1)
        patterns.append({"name": name, "regex": regex})
    return patterns


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="diffsec",
        description="Differential security reconnaissance: find unpatched "
        "siblings of a fixed bug pattern.",
    )
    ap.add_argument("repo", help="path to the git repository")
    ap.add_argument("--from", dest="from_ref", required=True, help="stable ref")
    ap.add_argument("--to", dest="to_ref", required=True, help="patched ref")
    ap.add_argument(
        "--scope", action="append", default=[],
        help="pathspec glob to restrict analysis (repeatable). "
        "e.g. 'packages/**/src/**/*.ts'",
    )
    ap.add_argument(
        "--exclude", action="append", default=[],
        help="pathspec glob to exclude (repeatable). e.g. '**/*.test.ts'",
    )
    ap.add_argument(
        "--pattern", action="append", default=[],
        help="inline pattern as name=regex (repeatable)",
    )
    ap.add_argument("--patterns", help="path to a patterns JSON file")
    ap.add_argument(
        "--min-score", type=int, default=2,
        help="minimum security signal score for a commit (default 2)",
    )
    ap.add_argument(
        "--out", default="diffsec-report",
        help="output path stem; writes <stem>.json and <stem>.md",
    )
    args = ap.parse_args(argv)

    try:
        repo = GitRepo(Path(args.repo).resolve())
        patterns = load_patterns(args)
        report = analyze(
            repo,
            args.from_ref,
            args.to_ref,
            args.scope,
            args.exclude,
            patterns,
            args.min_score,
        )
    except (GitError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"diffsec: error: {e}", file=sys.stderr)
        return 2

    json_path = Path(f"{args.out}.json")
    md_path = Path(f"{args.out}.md")
    json_path.write_text(json.dumps(asdict(report), indent=2))
    md_path.write_text(render_markdown(report))

    n_sib = sum(len(p.unpatched_siblings) for p in report.patterns)
    print(
        f"diffsec: {len(report.security_commits)} security commit(s), "
        f"{n_sib} unpatched sibling(s) across {len(report.patterns)} pattern(s)."
    )
    print(f"diffsec: wrote {json_path} and {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

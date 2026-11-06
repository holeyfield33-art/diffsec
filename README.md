# diffsec

Differential security reconnaissance over a git repo. Zero dependencies
(Python 3.9+ stdlib). Never touches the working tree. No network.

## The one idea

Diffing a stable ref against a patched ref can **only rediscover bugs the
maintainer already fixed**. The patched ref *is* the patch. So the diff is not
the product — it's a *teacher*. For each fix, you learn a bug **pattern**; the
only novel-capable leads are places that same pattern lives in code the patch
**did not touch** (unpatched siblings), and because those are still live you can
confirm them without pre-disclosing a fixed bug.

`diffsec` does the mechanical half of that method and leaves judgement to you (or
an agent). It never declares a vulnerability. It produces grounded evidence.

## Usage

```sh
python3 diffsec.py <repo> \
  --from <stable-ref> --to <patched-ref> \
  --scope 'src/**/*.ts' --exclude '**/*.test.ts' \
  --patterns patterns.json \
  --out report
```

Writes `report.json` (for an agent to consume) and `report.md` (to skim).

Patterns can also be inline and repeatable: `--pattern 'name=regex'`.
Scope/exclude use git pathspec globs and are repeatable.

## What it outputs

1. **security_commits** — commits between the refs whose message scores on a
   weighted security vocabulary (CVE/GHSA/bypass/harden/...), ranked, with a
   breaking-change bonus. Each lists the **companion test files** it added or
   changed — those document the maintainer's intent for the fix.
   *Context only. Never a finding.*

2. **patterns[].unpatched_siblings** — the primary product. For each pattern:
   the full call-site surface at `--to`, minus the sites the patch touched. Each
   sibling carries two triage signals:
   - `references_fix_mechanism` — does the sibling file mention the fix
     mechanism (the pattern's `intent_probe`) at all? `false` is suspicious.
   - `intent_test_hits` — test lines mentioning this module **and** the fix
     mechanism. A hit usually means a **negative control exists** (the behaviour
     is intended) — read those lines before claiming anything.

   The strongest unpatched candidate is `references_fix_mechanism=false` **and**
   `intent_test_hits=none`.

## Output contract (for agent consumers)

The JSON is the agent-facing surface. Rely on these top-level fields:
`schema_version` (currently `"1"` — check it before parsing), `meta_warning`,
`security_commits[]`, and `patterns[].unpatched_siblings[]`. Process exit codes:
`0` success, `2` usage/environment error (message on stderr).

**`intent_test_hits: none` is necessary, not sufficient.** The probe matches a
module's hyphenated directory name, as a whole identifier, on the same line as
the intent term. It deliberately does *not* match camelCase symbols (`emailOtp`)
or bare substrings (a `"otp"` token inside `emailOTPClient`): those collide
with plugin-registration lines (`emailOTPClient()` beside `twoFactorClient()`)
and would wrongly credit an uncontrolled sibling with a control. The trade-off
is recall — a control that names the module only by a camelCase symbol, or
lives outside the searched tests, is missed. Treat `none` as "look here first,"
not "no control exists" — read the sibling's source and tests before concluding
anything.

## Pattern file

```json
{
  "patterns": [
    {
      "name": "session-cookie-write",
      "regex": "setSessionCookie|setCookieCache",
      "scope": ["src/**/*.ts"],
      "exclude": ["**/*.test.ts"],
      "intent_probe": "asSignInGate|twoFactor|2fa"
    }
  ]
}
```

`regex` finds the pattern surface. `intent_probe` is the gate/fix mechanism
whose **absence** in a sibling is suspicious and whose **presence** in a test
signals intended behaviour. The tool is domain-agnostic; this file is the only
place target-specific knowledge lives.

## Honest limitations (read these)

- **Signal scoring is a ranking, not a gate.** A real fix can hide behind a dull
  "refactor" subject; `--min-score 0` surfaces everything.
- **Surface grep is approximate.** Regex over source misses dynamic dispatch and
  over-matches comments. Siblings are *candidates*, not confirmed call-sites.
- **`intent_probe` is a heuristic.** A test mentioning a module + the mechanism
  is evidence of a negative control, not proof. Read the cited lines.
- **It cannot extract the invariant for you.** It surfaces the diff, the
  companion tests, and the sibling set; understanding *what* the fix guarantees
  is the human/agent's job. That's by design — pretending to auto-understand
  semantics is how these tools produce false findings.
- **Matching is case-insensitive**, to catch prose-caps terms (`2FA`, `CSRF`).

## Tests

```sh
python3 -m unittest test_diffsec
```

Integration tests build a throwaway git repo (patched site, ungated sibling,
camelCase-only negative control) and assert the triage.

## Validated against

`better-auth` `v1.7.16 -> v1.8.0-beta.5`: unguided, it ranks `#12202 "harden
authentication flows"` top, flags its companion `two-factor.security.test.ts`,
and with the session-cookie pattern correctly marks `magic-link` as intended
(negative control at `two-factor.test.ts:2832`) while leaving `email-otp`,
`siwe`, `one-tap` et al. as ungated candidates to inspect.

The full report (markdown + JSON) is in [`examples/`](examples/).

# diffsec report: repo

`v1.7.16` -> `v1.8.0-beta.5`

> **Read this first.** Everything in the from..to diff is a fix the maintainer already made: known, fix-in-flight, zero bounty novelty, and unsafe to write up as a pre-patch exploit. Do NOT treat the security_commits list as findings. The only novel-capable leads are unpatched_siblings -- pattern call-sites the patch did not touch -- and even those are hypotheses until a negative control is checked.

## Unpatched siblings (the only novel-capable leads)

### pattern `session-cookie-write`  (`/setSessionCookie|setCookieCache/`)

- surface: 27 file(s) match the pattern at `v1.8.0-beta.5`
- patched by this diff: 5 file(s)
- **unpatched siblings: 22 file(s)**

  patched (already-handled ground):
  - `packages/better-auth/src/api/routes/sign-up.ts`
  - `packages/better-auth/src/plugins/anonymous/index.ts`
  - `packages/better-auth/src/plugins/organization/routes/crud-invites.ts`
  - `packages/better-auth/src/plugins/phone-number/routes.ts`
  - `packages/better-auth/src/plugins/two-factor/index.ts`

  | sibling | refs fix mechanism? | negative-control test hits |
  |---|---|---|
  | `packages/better-auth/src/api/routes/callback.ts:5` | **no** | none |
  | `packages/better-auth/src/api/routes/email-verification.ts:9` | **no** | none |
  | `packages/better-auth/src/api/routes/session.ts:19` | **no** | 5 (anon.test.ts:790, two-factor.security.test.ts:63, two-factor.security.test.ts:217, two-factor.security.test.ts:254, two-factor.security.test.ts:286) |
  | `packages/better-auth/src/api/routes/sign-in.ts:13` | **no** | 5 (two-factor.attempt-cap.test.ts:13, two-factor.security.test.ts:32, two-factor.security.test.ts:63, two-factor.security.test.ts:217, two-factor.security.test.ts:254) |
  | `packages/better-auth/src/api/routes/update-session.ts:5` | **no** | none |
  | `packages/better-auth/src/api/routes/update-user.ts:6` | **no** | none |
  | `packages/better-auth/src/cookies/index.ts:157` | yes | 4 (two-factor.security.test.ts:63, two-factor.security.test.ts:187, two-factor.security.test.ts:195, two-factor.security.test.ts:217) |
  | `packages/better-auth/src/plugins/admin/routes.ts:14` | **no** | 1 (types.test.ts:8) |
  | `packages/better-auth/src/plugins/email-otp/routes.ts:12` | **no** | none |
  | `packages/better-auth/src/plugins/magic-link/index.ts:9` | **no** | 1 (two-factor.test.ts:2832) |
  | `packages/better-auth/src/plugins/multi-session/index.ts:14` | **no** | none |
  | `packages/better-auth/src/plugins/oauth-popup/index.ts:316` | **no** | none |
  | `packages/better-auth/src/plugins/oauth-proxy/index.ts:16` | **no** | none |
  | `packages/better-auth/src/plugins/one-tap/index.ts:12` | **no** | none |
  | `packages/better-auth/src/plugins/one-time-token/index.ts:11` | **no** | none |
  | `packages/better-auth/src/plugins/organization/routes/crud-org.ts:5` | **no** | none |
  | `packages/better-auth/src/plugins/organization/routes/crud-team.ts:9` | **no** | none |
  | `packages/better-auth/src/plugins/siwe/index.ts:6` | **no** | none |
  | `packages/better-auth/src/plugins/two-factor/otp/index.ts:5` | yes | 5 (client.test.ts:635, two-factor.account-lockout.test.ts:146, two-factor.account-lockout.test.ts:147, two-factor.account-lockout.test.ts:195, two-factor.account-lockout.test.ts:200) |
  | `packages/better-auth/src/plugins/two-factor/totp/index.ts:7` | yes | 5 (two-factor.attempt-cap.test.ts:70, two-factor.security.test.ts:473, two-factor.test.ts:81, two-factor.test.ts:337, two-factor.test.ts:378) |
  | `packages/better-auth/src/plugins/two-factor/verify-two-factor.ts:5` | yes | 1 (two-factor.account-lockout.test.ts:17) |
  | `packages/better-auth/src/plugins/username/index.ts:11` | **no** | 1 (two-factor.security.test.ts:32) |

  _A sibling with references_fix_mechanism=false AND no intent_test_hits is the strongest unpatched-candidate. A sibling with intent_test_hits likely has a negative control (intended behaviour) -- read those test lines before claiming anything._

## Security-signal commits (context only -- NOT findings)

### `de9fb2b91` score 8 [BREAKING]
fix!: harden authentication flows (#12202)

- signals: auth(enticat|ori), harden
- files touched: 13

### `f3a687965` score 2
chore: sync main to next

- signals: token
- files touched: 0

### `ec0afdef5` score 2
fix(device-authorization)!: record one decision per device code (#11772)

- signals: auth(enticat|ori)
- files touched: 1

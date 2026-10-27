# AuditCanvas — Hackathon Build Log

**Event:** Meta Global AI Developer Hackathon (Meta × Cerebral Valley)
**Track:** Push the Frontier
**Submission deadline:** Nov 4, 2026, 9:00 PM ET (Nov 5, 8:00 AM Dhaka)
**Design spec:** `SPEC.md` (v2.2, locked) — also copied to `docs/SPEC.md`

## What AuditCanvas is

> Turn real security evidence into verified, understandable remediation.

AuditCanvas scans a website with a deterministic engine, stores the
evidence, and then lets a reasoning model (Muse Spark) do the part
scanners are bad at: explaining impact, prioritizing fixes, and arguing
against its own findings before anything is presented as settled.

**The scanner decides what exists; the model decides what it means.**
The model may explain, rank, and dispute severity. It may never create,
delete, or silently downgrade a finding.

## How the reasoning layer works

Five stages, in order:

1. **Deterministic scanner** — eight frozen check groups (below) produce
   check results in exactly four outcomes: Pass / Finding / Inconclusive /
   Not assessed. Inconclusive never counts as a pass.
2. **Evidence validator** — every result references stored evidence by
   stable ID (`ev-0001`, …). Evidence is snippets, not bodies; redaction
   happens before storage and before any model call. Set-Cookie is stored
   as attribute flags only, never values.
3. **Muse Spark auditor** — at most **three model calls per scan**, no
   agent loops: (1) auditor pass (impact, prioritization, explanations,
   fix drafts), (2) a separate **adversarial refutation** call that sees
   only the claim plus stored evidence, never the auditor's reasoning,
   (3) summary / fix-pack drafting.
4. **Report validator** — rejects auditor output that references unknown
   evidence IDs, quotes text not present verbatim in the stored evidence,
   or violates the schema.
5. **Report** — deterministic scores the model cannot touch: **Risk**
   (severity-weighted, any confirmed high caps the grade band),
   **Coverage** (share of attempted checks that reached a verdict),
   **Confidence** (share of findings on direct evidence vs inference),
   plus a reproducibility stamp (scanner version, rules version, model
   ID, timestamp, target, scan policy, data-snapshot versions with stale
   warnings).

If the model API is missing or fails, the report falls back to the
**engine-only deterministic report** and says so. A failed call is a
visible state, never a silent pass.

Refutation outcomes are exactly: Survived refutation / Confidence
reduced / Not substantiated. Only the deterministic evidence assessment
can mark a finding Not substantiated; a model argument alone can at most
reduce confidence. Nothing is ever deleted.

Exploit chains are labelled Supported / Conditional / Unproven.
Conditional renders dashed and is never presented as confirmed; Unproven
is not rendered as a path. CORS + cookie flags alone never prove session
theft (HttpOnly governs script access; Secure governs transport).

## The eight scanner groups (frozen)

1. Security headers (HSTS, CSP, XCTO, Referrer-Policy, Permissions-Policy, framing)
2. TLS (protocol, chain, hostname, expiry)
3. Cookies (Secure, HttpOnly, SameSite, SameSite=None discipline)
4. CORS (a finding requires credentials allowed **with** origin reflection or `*`; wildcard alone is an info observation)
5. Exposed paths with soft-404 baselining (a 200 that matches the baseline is Inconclusive, never a finding)
6. Client stack + CVEs matched against affected version ranges in a versioned NVD snapshot
7. Email posture: SPF/DMARC with the DNS error taxonomy (NXDOMAIN/timeout/SERVFAIL = Inconclusive; only a confirmed empty answer counts as missing)
8. Redirects + mixed content (open redirect only when a bounded probe's Location is verified off-origin)

## Safety model

- SSRF-safe fetch layer: http/https on ports 80/443 only; every A/AAAA
  record resolved and validated; private/loopback/link-local/multicast/
  reserved and IPv4-mapped IPv6 rejected (one bad address poisons the
  set); connections pinned to a validated IP with TLS SNI and certificate
  hostname verification bound to the original hostname; max 5 redirects,
  each hop re-validated, scheme/port changes refused; per-scan request
  budget, per-request timeout, total deadline, response-size cap.
- Unverified targets always get the restricted passive policy (no
  probes, small budget), whatever the user attests. The full check set
  runs only on verified or demo-allowlisted targets.
- All checks are non-destructive and read-only.

## Build log

### Night 0 — Oct 28, 2026: scaffold + scanner core

- Public repo created; spec committed as the design reference.
- Next.js App Router scaffold (JavaScript, lightweight) with the
  stepwise scan architecture: the client drives the scan as one short
  API step per check group (`/api/scan/start`, `/api/scan/step`,
  `/api/scan/[id]`).
- Evidence schema lib: stable evidence/finding IDs, four outcomes,
  redaction-by-construction, validators.
- SSRF-safe fetch layer per spec (above).
- All eight deterministic scanner groups implemented.
- Deterministic scoring (Risk / Coverage / Confidence) with the
  high-severity grade cap.
- Auditor layer: the three call sites exist behind env config
  (`META_API_KEY` / `META_MODEL_ID`), with the report validator and the
  engine-only fallback. **No real key is wired yet** — with no env set,
  reports carry the explicit `engine-only` status.
- Seeded demo target at `/api/demo-target` (deliberately vulnerable,
  owned by this app) powering Judge mode's "Run the seeded demo".
- Judge-mode entry skeleton: product name, "See the auditor reason, not
  just scan", exactly two entry points (seeded demo, sample reports).
  Sample reports are honestly empty until Day 7.
- Fixture suite (`fixtures/server.mjs`): vulnerable, hardened,
  slow/timeout, and garbage responders, plus an HTTPS vulnerable origin
  under a throwaway local CA. `scripts/verify.mjs` asserts the scanner's
  verdicts against them.
- **Verified Night 0:** production build passes; fixture suite
  **44/44 assertions pass**; live API smoke test (start → 8 steps →
  report) against the seeded demo target completes with report
  integrity ok and the engine-only auditor state shown.

### Known stubs and open verifications (honest list)

- **Meta model ID and structured-output support on the account are not
  yet verified.** The auditor reads both from env and fails cleanly;
  Night 0 deliberately does not assume a model ID. First task when the
  key is wired: one real auditor call end to end.
- **Refutation and summary passes are call-site stubs** (explicit
  `not-run` states) until the Day 4 pipeline build.
- **CVE snapshot is a hand-seeded stub** (`src/lib/cve-snapshot.json`,
  version `stub-2026-10-28`) covering a few well-known library ranges
  for offline development and fixture tests. Entries must be verified
  against NVD and the snapshot replaced with a dated pull before any
  real report is published; the snapshot version travels in every
  report's reproducibility stamp with a stale warning after 90 days.
- **DNS TXT ownership verification is not built** (later spec day);
  until then only server-allowlisted demo hosts get the full policy.
- Scan sessions are in-memory; report persistence, 7-day expiry, and
  one-click delete land with the report-lifecycle work.
- Downloads (`auditcanvas-evidence.json`, `auditcanvas-fix-pack.zip`),
  the visual canvas, and the diff view are later spec days.

## Next steps

1. Wire the real Meta API key in env; verify the model ID and
   structured outputs with one live auditor call.
2. Auditor pass live, then the adversarial refutation pass.
3. Canvas report view; evidence JSON + fix-pack downloads.
4. Judge mode polish and the seeded sample-report set.
5. Hardening pass (budgets, cooldowns, quotas), rehearsal, submission.

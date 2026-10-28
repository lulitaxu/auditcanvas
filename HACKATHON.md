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

### Day 4-5 — Oct 28, 2026: chains, refutation, downloads, verification, canvas

- **Exploit chains engine** (`src/lib/chains.js`): chain proposals arrive
  inside the auditor pass (call 1 of 3) and are never trusted — the
  server validates every finding/evidence ID and re-derives the
  classification from per-chain-type evidence requirements in code. The
  catalog has three types (cors-data-exposure,
  plaintext-session-exposure, known-vuln-library-exposure). The spec's
  corrected CORS example is enforced structurally: a CORS chain needs an
  allowed/reflected untrusted origin AND credentials allowed AND a
  sensitive response readable cross-origin; cookie flags satisfy none
  of these and a flags-only proposal classifies Unproven. Supported
  renders solid, Conditional renders dashed, Unproven is not rendered
  as a path (Technical mode shows it as rejected reasoning). Structurally
  invalid proposals (unknown IDs, unknown type) are rejected outright.
  Without a model key the block reports its explicit not-run state; the
  engine never fabricates chains.
- **Refutation pass** (`src/lib/refutation.js`): separate adversarial
  call site (call 2 of 3) fed only the claim + stored evidence. The
  deterministic evidence assessment (per-check precondition registry)
  alone decides the outcome: Survived refutation / Confidence reduced /
  Not substantiated. A model argument can at most reduce confidence.
  Scope = high-severity findings + Supported-chain nodes. Refutation
  runs BEFORE final scoring in the pipeline: not-substantiated claims
  stop driving Risk (finding stays in the report), confidence-reduced
  findings lower the Confidence score. Report entries carry the four
  spec fields per challenged finding. Without a key: explicit
  "Refutation not run" state.
- **Downloads** (`src/lib/downloads.js`): `auditcanvas-evidence.json`
  (schemaVersion in every bundle; every finding resolves to evidence
  inside the file) and `auditcanvas-fix-pack.zip` (dependency-free ZIP
  writer; one suggested-patch file per finding, header carries finding
  ID + evidence IDs + detected stack + conditions + placement; only
  stack-applicable variants generated). Served from
  `/api/scan/[id]/evidence` and `/api/scan/[id]/fix-pack`.
- **DNS TXT ownership verification** (`src/lib/ownership.js`): token
  bound to the exact hostname, 15-minute challenge at
  `_auditcanvas.<host>`, DNS error taxonomy respected (a resolver error
  is inconclusive, never "missing"). Verified hosts unlock the full
  policy; verification state is stored on the scan session and travels
  into the report and evidence bundle. Unverified targets keep the
  restricted passive policy.
- **Judge mode + canvas**: the first screen is Judge mode with NO URL
  input (seeded demo + sample reports); scanning your own site is the
  separate normal flow, with the DNS verification panel beside it. The
  report view renders the evidence graph (Assets → Observations →
  Findings → Fixes) as SVG with chain paths per the rendering rules,
  click-a-finding evidence tracing, Owner/Technical modes, the three
  deterministic scores with their formulas, and download buttons.
- **Verified Day 4-5:** production build passes; fixture suite
  **65/65 assertions** (44 Night-0 + 21 new: chain classification incl.
  the corrected CORS example and unknown-ID rejection, refutation
  outcomes and their Risk/Confidence interaction, downloads, ownership
  lifecycle); live API smoke test (start → 8 steps → finalized report →
  both downloads → verify endpoints) against the seeded demo target:
  21 findings, Risk F/100, auditor engine-only, chains and refutation
  in their explicit not-run states.

### Day 6-7 — Oct 28, 2026: verified CVE snapshot, rescan + diff

- **CVE snapshot replaced with a verified NVD pull** (see the stub
  note below for the corrections verification produced).
- **Rescan + scan diff** (`src/lib/diff.js`, `POST /api/scan/[id]/rescan`,
  `GET /api/scan/[id]/diff`): a rescan is a fresh session for the same
  target under the same policy, linked to its predecessor
  (`rescanOf`, stored on the session, the report, and the audit log).
  The diff classifies every finding by stable check identity as
  Resolved / New / Persistent / Severity-changed / Could-not-repeat,
  with before/after Risk, Coverage and Confidence. Resolution is only
  claimed when the rescan's fresh evidence re-ran that check area to a
  verdict: a check that came back Inconclusive, or whose group never
  reached a verdict, is Could-not-repeat — never silently "fixed".
  (One subtlety the diff has to handle: a check's slug varies with its
  outcome — the pass twin of `headers.csp-unsafe-inline` is
  `headers.csp` — so disappearance is confirmed at check-family level,
  documented in diff.js.) The report UI gains a "Rescan this target"
  action and a "What changed since the previous scan" section with the
  score movement. The fixture suite flips the vulnerable origin to its
  hardened behavior at the SAME origin, so the diff assertions run a
  genuine fix-and-rescan: all 24 vulnerable-fixture findings resolve,
  risk goes to grade A / 0.
- **Verified Day 6-7:** production build passes; fixture suite
  **73/73 assertions** (65 previous + 8 diff: resolved set, reverse
  diff as new findings, identity diff all-persistent, the
  could-not-repeat honesty rule, severity-changed); live API smoke
  test against the seeded demo target (start → 8 steps → report →
  rescan → 8 steps → diff): 22 findings, all persistent against the
  unchanged target, zero score movement, and the guard rails hold
  (diff on a non-rescan is 400, rescan of an unknown scan is 404).

### Day 8 — Oct 28, 2026: sample reports attempted (blocked by sandbox egress), submission prep

- **Preloaded sample reports: attempted properly, blocked by this
  VM's network — placeholder shipped, generation is one command after
  deploy.** `scripts/generate-samples.mjs` drives the app's own
  pipeline (createScan → 8 group steps → finalizeReport) against
  nyktos.tech and cliphaus.dev and writes a sample file only if the
  scan genuinely reached the target (≥1 recorded HTTP response and ≥1
  check at a verdict). Run on 2026-10-28, both targets tripped the
  gate: 0 HTTP responses, 11 Inconclusive / 2 Not assessed each.
  Root cause, two layers, both in the sandbox rather than the sites
  (both return 200 through the proxy):
  1. The VM's resolver answers both hostnames with synthetic
     198.18.230.30 / 198.18.230.31 — the 198.18.0.0/15 benchmarking
     range — and the scanner's address validation correctly refuses
     them as reserved ("Refusing nyktos.tech: 198.18.230.30 is
     reserved (198.18.0.0/15 benchmarking)").
  2. Even bypassing DNS (real Cloudflare addresses fetched over DoH:
     104.21.26.144 / 172.67.136.129 for nyktos.tech, 172.67.208.170 /
     104.21.93.103 for cliphaus.dev), direct TLS to the real IPs fails
     with "wrong version number": the sandbox transparently intercepts
     direct egress, and the scanner connects directly by design
     (pinned IPs, no proxy support — by spec, not oversight).
  Storing the all-Inconclusive runs as "scans" would have been
  fabrication, so no sample files exist. Instead the Judge-mode slot
  is fully wired (`src/lib/samples.js`, `/api/samples`,
  `/api/samples/[slug]`, saved-result cards with stamp + scores,
  ReportView rendering with scan actions correctly absent) and shows
  an explicit "generated after deploy" placeholder naming both
  pending targets and the reason. After deploy, one run of the
  generator from an environment with ordinary egress fills the slot.
- **Submission draft** written to `SUBMISSION.md` (cerebralvalley.ai
  fields; demo URL and video link left as marked placeholders).
- **Demo video script** written to `DEMO-SCRIPT.md`: timed 3-minute
  run-of-show around "See the auditor reason, not just scan", with a
  pre-recording checklist (fixtures green, key in env, demo target
  allowlisted).
- **Verified Day 8:** production build passes; fixture suite still
  73/73; `/api/samples` returns the empty list with the two expected
  targets, and the Judge-mode placeholder renders both pending slots.

### Known stubs and open verifications (honest list)

- **Meta model ID and structured-output support on the account are not
  yet verified.** The auditor reads both from env and fails cleanly;
  Night 0 deliberately does not assume a model ID. First task when the
  key is wired: one real auditor call end to end.
- **Refutation and chains are fully wired** (validation, classification,
  deterministic assessment, scoring interaction) but have only ever run
  their not-run states: the first live exercise waits on the Meta key,
  exactly like the auditor pass.
- **CVE snapshot is now a verified NVD pull** (`src/lib/cve-snapshot.json`,
  version `nvd-2026-10-28`): all 20 entries across the five fingerprinted
  libraries (jQuery, Bootstrap, Lodash, AngularJS, Moment.js) checked
  against their NVD records (affected CPE ranges + CVSS v3.x severity)
  via the NVD API 2.0 on 2026-10-28. Verification corrected four seeded
  ranges (Bootstrap CVE-2019-8331 4.x starts at 4.3.0, CVE-2018-14042
  runs to <4.1.2 not <4.0.2, Lodash CVE-2020-8203 fixed in 4.17.20 not
  4.17.19, jQuery CVE-2020-11023 starts at 1.0.3) and dropped invented
  lower bounds NVD does not carry. Two checked CVEs were deliberately
  excluded: CVE-2024-6484 is REJECTED in NVD, and CVE-2022-24785 is
  scoped to npm server users, not browser-loaded Moment.js. The snapshot
  version travels in every report's reproducibility stamp with a stale
  warning after 90 days.
- Scan sessions are STATELESS (production fix, 2026-10-28): the first
  deployed build kept sessions in one process's memory, so on Vercel
  every step after /start failed with "Unknown scan ID" and reports
  finalized empty. The flow is now descriptor → per-group steps (each
  re-derives the policy server-side and returns its results +
  evidence) → /api/scan/finalize, which re-validates, re-redacts,
  dedupes and renumbers everything server-side before the pipeline
  runs; finalized reports are held by the client and posted back for
  downloads/diffs. The seeded demo target now resolves to the full
  policy by a server-side self-origin rule (the exact /api/demo-target
  path on the app's own origin), instead of needing its production
  hostname in a config allowlist. Still open: durable report
  persistence, 7-day expiry, and one-click delete land with the
  report-lifecycle work; per-IP cooldown/quota counters and the DNS
  verification store remain per-process best-effort on serverless.
- The summary pass (call 3 of 3) remains a call-site stub: the fix pack
  is generated deterministically so it exists in every report; only the
  prose summary waits on the live auditor.
- Preloaded real sample reports (nyktos.tech, cliphaus.dev) for Judge
  mode: the slot is wired end to end and the generator exists, but the
  scans themselves are blocked from the build sandbox (see the Day 8
  entry for the two-layer egress blocker). The slot shows its explicit
  "generated after deploy" placeholder until
  `scripts/generate-samples.mjs` runs once post-deploy.

## Next steps

1. Wire the real Meta API key in env; verify the model ID and
   structured outputs with one live auditor call, then exercise chains
   and refutation live for the first time.
2. After deploy: run `scripts/generate-samples.mjs` once to fill the
   Judge-mode sample slot with the real nyktos.tech / cliphaus.dev
   reports, labelled Saved result — then re-check labels, timestamps,
   and versions against the scan records. (Scan diff + fix verification
   shipped Day 6-7; the samples slot and generator shipped Day 8,
   blocked only by sandbox egress.)
3. Auditor evaluation suite (fabricated-evidence and false-positive
   fixtures; precision gained / true findings retained).
4. Report lifecycle: persistence, 7-day expiry, one-click delete.
5. Hardening pass (budgets, cooldowns, quotas), rehearsal, submission.

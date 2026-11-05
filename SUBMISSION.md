# AuditCanvas — cerebralvalley.ai submission draft

_Draft prepared Oct 28, 2026 for the Meta Global AI Developer Hackathon
submission form, revised Nov 3, 2026 for the fallback submission.
Copy each field into the form; the one remaining bracketed placeholder
(demo video) is filled in last, as noted at the bottom. Everything
claimed below is limited to what is built and verified in the repo;
the provider situation is stated openly in the auditor section and in
the honesty notes at the end._

---

## Project name

AuditCanvas

## Track

Push the Frontier

## One-liner

AuditCanvas turns real security evidence into verified, understandable
remediation: a deterministic scanner gathers the evidence, and an AI
auditor reasons over it — explaining impact, building evidence-checked
attack chains, and arguing against its own findings before anything is
presented as settled.

## Live demo URL

https://auditcanvas.vercel.app

## Demo video

https://www.youtube.com/watch?v=RIXRpLfCDAE (unlisted, 3:10)

## Repository

https://github.com/lulitaxu/auditcanvas

## Description

### The problem

Website security scanners produce lists. A typical report says "missing
Content-Security-Policy, medium" and stops there — no proof, no sense
of what an attacker would actually do with it, no way to tell a real
exposure from a false positive, and no way to prove a fix worked short
of paying for another scan. Owners either panic over noise or learn to
ignore the report entirely. The newer AI wrappers make this worse, not
better: they narrate findings they cannot cite, and a fluent paragraph
is not evidence.

### What AuditCanvas does

Point AuditCanvas at a website you own. A deterministic engine runs
nine check groups modelled on the OWASP Web Security Testing Guide —
security headers, TLS, cookies, CORS, exposed paths (with soft-404
baselining), exposure and secrets (env-file variants, anchored secret
patterns in first-party JavaScript — evidenced as pattern class and
fingerprint, never the secret — and a host-gated shallow Firebase
probe), client stack and CVE matching against affected version
ranges in a versioned NVD snapshot, email posture (SPF/DMARC with a
proper DNS error taxonomy), and redirects and mixed content. Every
check ends in exactly one of four outcomes: **Pass, Finding,
Inconclusive, or Not assessed** — and Inconclusive is never counted as
a pass. Every result is backed by stored, redacted evidence with
stable IDs (headers, certificate fields, DNS answers; never bodies,
never cookie values).

The results render as an evidence graph — Assets → Observations →
Findings → Fixes — so any finding can be traced down to the exact
response headers, DNS answer, or certificate fields that support it.
Scoring is deterministic and printed in the report: **Risk**
(severity-weighted over confirmed findings only; any confirmed high
caps the grade band), **Coverage** (checks that reached a verdict out
of checks attempted), and **Confidence** (findings backed by direct
evidence versus inference). After a fix, a rescan produces a diff —
Resolved / New / Persistent / Severity-changed / Could-not-repeat —
and a finding is only called Resolved when fresh evidence re-ran its
check to a verdict. Every report carries a reproducibility stamp:
scanner version, rules version, model ID, timestamp, target, scan
policy, and data-snapshot versions.

Safety is specified, not hand-waved. The fetch layer only speaks
http/https on ports 80/443, resolves and validates every A/AAAA
address, rejects private, loopback, link-local, multicast, reserved,
and IPv4-mapped addresses, connects to a pinned validated IP with TLS
SNI and certificate hostname verification bound to the original
hostname, and re-validates every redirect hop. Per-scan budgets,
timeouts, deadlines, and response-size caps apply throughout. Ownership
verification is one method done properly: a DNS TXT token bound to the
exact hostname. Verified targets unlock the full check set; unverified
targets always run a restricted passive policy.

Judge mode — the first screen — has no URL input at all. It offers a
one-click scan of a seeded, deliberately vulnerable demo target (ours,
allowlisted), with progress streaming by check group and the canvas
building live, plus preloaded sample reports from real scans of our
own sites, each labelled "Saved result" with its timestamp, scanner
version, and model ID. Reports export as `auditcanvas-evidence.json`
(a versioned, independently inspectable evidence bundle) and
`auditcanvas-fix-pack.zip` (one suggested-patch file per finding,
carrying its finding ID, evidence IDs, applicable stack, conditions,
and placement).

### How the AI auditor is used (and which model runs it)

The scanner decides what exists; the model decides what it means. The
model may explain, rank, and dispute severity. It may never create,
delete, or silently downgrade a finding, and it never touches the
scores.

**Which model:** this auditor layer was designed and built for Muse
Spark on the Meta Model API, and the live deployment runs **Muse
Spark (`muse-spark-1.3`)**. During part of the hackathon window the
project's Meta account was restricted over a failed payment-method
authorization hold, so no Meta API key could be issued and no Muse
Spark call could be made; in that period the demo ran the identical
auditor on a Gemini fallback (`gemini-3.5-flash-lite`, verified live
Nov 3-4, 2026). The auditor contract is provider-agnostic by
construction — the same prompts, output schemas, report validator,
chain classifier, and refutation assessment sit in front of a
server-side provider switch (`AUDITOR_PROVIDER`). On Nov 5, 2026,
with the restriction lifted and a key issued, the deployment was
switched back to Muse Spark through that switch and verified live
end to end: the seeded demo returns a fully annotated report stamped
provider `meta`, model `muse-spark-1.3`, with validated attack-path
chains rendered and the refutation pass completing. Muse Spark
generation on the full auditor payload is slow (a finalize takes
roughly two minutes), so the Meta call path uses a single attempt
with a long timeout inside a raised finalize budget; the fixture
suite still passes 156/156. Every report's reproducibility stamp
names the provider and model that actually produced it, so nothing
about this is hidden in the output.

The auditor is used in at most **three bounded calls per scan** — no
agent loops, strict output schemas, fixed evidence inputs, a bounded
timeout per call, and a per-scan cost cap:

1. **Auditor pass.** Given the stored evidence, the auditor explains
   each finding's impact on this kind of site, orders a fix-first
   list (maximum five) with impact/effort reasoning, drafts fixes,
   and proposes exploit chains. If the auditor judges a finding
   overstated, the report shows both positions — engine verdict and
   auditor note — and keeps the engine's.
2. **Refutation pass.** A separate adversarial call that receives
   only the finding claim and the stored evidence — never the
   auditor's reasoning, so it cannot anchor on it — and argues the
   strongest plausible false-positive case. A deterministic evidence
   assessment then decides the outcome: **Survived refutation**,
   **Confidence reduced**, or **Not substantiated**. Only the
   deterministic assessment can mark a claim not substantiated (the
   observation stays in the report; it stops driving the Risk score);
   a model argument alone can at most reduce confidence.
3. **Summary / fix-pack pass.** Drafts the plain-language summary and
   remediation prose. The fix pack itself is generated
   deterministically, so it exists in every report even if this call
   fails.

**Exploit chains** show how findings combine into an attack path.
Every chain is labelled "AI-derived attack path" and classified in
code as **Supported** (every required precondition observed in
evidence; renders solid), **Conditional** (at least one precondition
inferred, not observed; renders dashed, never presented as confirmed),
or **Unproven** (a required precondition absent; not rendered as a
path at all, visible in Technical mode only as rejected reasoning).
The server validates every evidence ID and re-derives the
classification from per-chain-type evidence requirements — for
example, a CORS chain to cross-origin data exposure requires an
allowed or reflected untrusted origin, credentials allowed, and a
sensitive response readable cross-origin. Cookie flags alone prove
none of that: HttpOnly governs script access to a cookie, Secure
governs its transport.

A **report validator** sits between the model and the report: auditor
output that references unknown evidence IDs, quotes text not present
verbatim in the stored evidence, or violates the schema is rejected.
If the model API is missing or fails, the report falls back to the
engine-only deterministic report and says so — a failed call is a
visible state, never a silent pass.

### What was built in the window

Everything in the repository was built during the hackathon window
(Oct 26 – Nov 4, 2026), from a locked design spec (SPEC.md, v2.2)
committed before the code:

- The SSRF-safe fetch layer and the eight frozen scanner groups plus
  the Exposure group (founder-approved addendum, SPEC.md 2026-10-29), with
  a fixture suite (vulnerable, hardened, slow/timeout, and garbage
  origins) that the scanner's verdicts are asserted against:
  **156/156 assertions green**, including zero findings on the hardened
  fixture and Inconclusive — never Pass — on malformed and hanging
  targets.
- The five-stage pipeline: deterministic scanner → evidence validator
  → AI auditor → report validator → report, with the
  stepwise scan architecture (one short API step per check group) so
  scans survive serverless timeouts.
- Exploit-chain validation and classification, the refutation pass
  with its deterministic evidence assessment, and their interaction
  with scoring (not-substantiated claims stop driving Risk;
  confidence-reduced findings lower Confidence).
- Deterministic scoring with the formulas printed in the report, the
  evidence-graph canvas with Owner and Technical modes, Judge mode
  with live streamed progress, DNS TXT ownership verification, the
  evidence bundle and fix-pack downloads, and rescan + diff with fix
  verification.
- A CVE snapshot pulled from the NVD API and verified entry by entry
  (version `nvd-2026-10-28`); verification corrected four seeded
  ranges and excluded two inapplicable CVEs before it shipped.

### Tech stack

Next.js 16 (App Router) and React 19, plain JavaScript, Node.js
runtime, zero runtime dependencies beyond Next/React. Deterministic
scanner and scoring in `src/lib/`; the auditor model sits behind a
server-side provider switch — built for Muse Spark via the Meta
Model API (`https://api.meta.ai/v1`, model ID read from environment,
never assumed in code); the live deployment runs Muse Spark, with
the Gemini fallback (`gemini-3.5-flash-lite`) retained behind the
same switch. CVE data: versioned snapshot from the NVD
API 2.0.
Dependency-free ZIP writer for the fix pack.

### Honesty notes (what is NOT claimed)

- The auditor layer — all three call sites, the report validator, the
  chain classifier, the refutation assessment, and the engine-only
  fallback — is built and wired, and its non-model logic is exercised
  by the fixture suite (156/156 assertions green on Nov 3, 2026).
  **Live-model verification is complete on both providers**: on
  Nov 3, 2026 the deployed app produced fully annotated reports
  (auditor pass and refutation pass both ok) stamped provider
  `gemini`, model `gemini-3.5-flash-lite`, and on Nov 5, 2026 —
  after the Meta account restriction lifted — the same verification
  passed on Muse Spark, stamped provider `meta`, model
  `muse-spark-1.3`, both passes ok, with chains and refutation
  entries in the report. The demo was not recorded against a mocked
  model.
- Preloaded sample reports are real scans of our own sites
  (nyktos.tech, cliphaus.dev) produced by the deployed app itself and
  saved with their reproducibility stamps; the samples now live in
  Judge mode show the same Muse Spark stamp as the live demo
  (regenerated through the deployed app on Nov 5, 2026, auditor
  annotated on both passes).
  No sample report in this project is hand-assembled.

---

## Fill-in order at submission time

1. ~~Deploy → paste the live URL~~ DONE Nov 3, 2026:
   https://auditcanvas.vercel.app is live, and the Judge-mode samples
   were regenerated through the deployed app the same day (Gemini
   fallback stamp, auditor annotated). Regenerated again Nov 5, 2026
   after the switch back to Muse Spark (meta stamp, auditor
   annotated).
2. Record the demo video from `DEMO-SCRIPT.md` (pre-recording
   checklist first, with the fallback addendum at the top) → paste
   the link into **[AFTER RECORDING]**.
3. ~~If the Meta restriction clears before the deadline and a Muse
   Spark scan verifies, update the auditor section~~ DONE Nov 5,
   2026: the restriction cleared, a Muse Spark scan verified live
   end to end, and this document was updated to match the live
   deployment.

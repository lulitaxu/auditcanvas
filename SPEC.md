# AuditCanvas — Meta Global AI Developer Hackathon spec (v2.2)

Track: **Push the Frontier** (software). Solo: Arz.
Window: Mon Oct 26, 2026 (kickoff 23:00 Dhaka) to Wed Nov 4, 9:00 PM ET.
Submit target: Nov 4 evening Dhaka, hours before the deadline, not at it.
Repo: NEW public repo `auditcanvas`. Everything in it is built inside the window.

v2 changes (post-review): SSRF specified properly, four-state check outcomes,
deterministic three-part scoring, evidence minimization and redaction, abuse
controls, stepwise scan architecture for serverless, evidence graph canvas,
scan diff + fix verification, an auditor evaluation suite, and scanner logic
corrected per the OWASP Web Security Testing Guide.

v2.1 changes (locked by Arz, 2026-10-26): four additions, no new scanner
groups and no extra model calls. (1) Exploit chains on the canvas, (2) a
refutation pass inside the existing second auditor call, (3) Judge mode
with one-click demo scan and preloaded real reports, (4) evidence bundle
and fix file downloads. All four are locked scope, not stretch ideas.

v2.2 changes (tightening review, 2026-10-26): the four features stay, the
implementation rules get stricter. Chains are classified supported /
conditional / unproven with per-chain-type evidence requirements, and the
v2.1 CORS chain example is corrected (cookie flags alone never prove
session theft). Refutation becomes a separate adversarial call with
three outcomes and a deterministic evidence assessment stage; the call
cap rises from two to three to pay for it. Judge mode gets saved-result
labelling and a fixed target with no URL input. Downloads get exact
artifact names, a versioned evidence schema, and suggested-patch
labelling. The 9-day plan is replaced with the revised allocation, and
Day 4 is explicitly bounded: strict schemas, fixed evidence inputs, no
multi-step agent loops.

## The promise (one line, everything serves it)

Turn real security evidence into verified, understandable remediation.

Point AuditCanvas at a website you own. It runs real, non-destructive checks,
and Muse Spark reasons over the evidence like an auditor: it explains impact,
prioritizes, and drafts fixes. It never invents a finding, and it can prove a
fix worked by rescanning.

## Design principles (non-negotiable)

1. **The scanner decides what exists; the model decides what it means.**
   Findings are created only by deterministic checks, each with a stable
   finding ID and evidence IDs. The model may explain, rank, and dispute
   severity. It may not create, delete, or silently downgrade a finding.
2. **Four outcomes, never two.** Every check ends as Pass, Finding,
   Inconclusive, or Not assessed. Inconclusive is never counted as a pass.
3. **Evidence is minimal and redacted by construction** (see Data rules).
4. **Restricted by default.** Unverified targets get a passive-only scan
   policy with small budgets, whatever the user attests.
5. **Deterministic scoring.** The formula is code, documented in the report.
   The model never touches the numbers; it may only annotate them.
6. **Success criterion (v2.2).** Not how many AI features appear on the
   canvas, but whether AuditCanvas can demonstrate, with evidence, that
   its reasoning produces a better audit than a conventional checklist.
   Every feature is judged against that sentence.

## Architecture

**Stepwise scan (serverless-safe).** No single long request and no assumed
background worker. The client drives the scan as a sequence of short API
steps, one per check group; each step is a bounded server route (strict
per-step timeout, request budget) that returns structured evidence and
progress. A scan can pause, resume, or be cancelled between steps. The final
report is assembled and persisted server-side; in-progress state lives with
the scan session, keyed by an unguessable ID.

**Five-stage pipeline.**
1. Deterministic scanner → raw observations with stable evidence IDs.
2. Evidence validator → schema checks, redaction, dedup, severity rules.
3. Muse Spark auditor → impact, prioritization, explanations, fix drafts.
4. Report validator → rejects any model output that references unknown
   evidence IDs, quotes text not present in the stored evidence (verbatim
   match), or violates the output schema. On rejection or API failure, the
   report falls back to the engine-only deterministic report. The demo can
   therefore never die with the API.
5. Report → risk/coverage/confidence, evidence graph, fix-first list, diff.

**Verify on Night 0 (do not assume):** the exact model ID available to Arz's
Meta Model API account, whether structured outputs are supported on it, and
rate/cost limits. The Oshudh wiring used muse-spark-1.1; Meta's docs also
list a muse-spark-1.3. The auditor layer reads the model ID from env and is
written against structured output with a JSON-parse fallback.

**Reproducibility stamp on every report:** scanner version, rules version,
model ID, scan timestamp, target, scan policy, and data snapshot versions
(CVE data carries a source + timestamp + stale warning when old).

## SSRF and target safety (specified, not hand-waved)

- Only http/https, only ports 80/443.
- Resolve the hostname; validate EVERY returned A/AAAA address: reject the
  whole set if any address is private, loopback, link-local, multicast,
  reserved, or an IPv4-mapped/compatible IPv6 form of one.
- Connect to a validated IP (pinning); preserve TLS SNI and certificate
  hostname verification against the original hostname. This kills DNS
  rebinding between validation and connect.
- Redirects: max 5, each hop re-validated end to end (resolve, validate,
  pin) before following. Scheme or port changes on redirect are refused.
- Per-scan request budget, per-request timeout, total scan deadline,
  response-size cap. One scan per target at a time; per-target cooldown;
  per-IP daily quota. Every scan records its authorization state
  (attested / verified / restricted) in an audit log.

## Scanner: eight groups, corrected logic

Methodology follows the OWASP Web Security Testing Guide. Each check emits
Pass / Finding / Inconclusive / Not assessed with evidence.

1. **Headers.** HSTS is judged on the HTTPS response; "missing" and
   "present but misconfigured" (short max-age, no includeSubDomains where
   relevant) are different findings. CSP is parsed per directive:
   unsafe-inline / unsafe-eval in script-src, wildcard sources, and
   missing object-src/base-uri are flagged specifically; a present CSP is
   never auto-called secure. Plus X-Content-Type-Options,
   Referrer-Policy, Permissions-Policy, frame-ancestors / X-Frame-Options.
2. **TLS.** Negotiated protocol version, certificate hostname match, chain
   validity, and expiry window (expired / <14 days / <30 days). A valid
   cert alone is never the whole verdict.
3. **Cookies.** Attributes read from actual Set-Cookie headers (Secure,
   HttpOnly, SameSite, path scope). Names are not trusted to identify
   sessions; findings state which cookies lack which attribute and mark
   session-likelihood as an inference, not a fact.
4. **CORS.** Wildcard alone is not called exploitable. The finding requires
   the dangerous combination: origin reflection or `*` WITH credentials
   allowed, tested with benign probe origins. Otherwise it is reported as
   a low/informational observation with the reasoning shown.
5. **Exposed paths.** Presence checks (/.git/HEAD, /.env, /wp-admin,
   listing signatures) with soft-404 baselining: first fetch a random
   nonexistent path; a "200" that matches the baseline signature is
   Inconclusive, never a finding. Content is never exploited, only the
   exposure signature is recorded.
6. **Client stack and CVEs.** Library versions detected from assets,
   normalized, and matched against affected version RANGES (not "any
   version below latest"). Version inferred from a filename or minified
   bundle is flagged "detection uncertain" and lowers confidence, not
   severity. CVE data: NVD, snapshot versioned and timestamped.
7. **Email posture.** SPF and DMARC via DNS with error taxonomy:
   NXDOMAIN, timeout, and SERVFAIL are Inconclusive; only a confirmed
   empty answer is "missing". DMARC policy (none → reject) graded.
8. **Redirects and mixed content.** Open-redirect only on a bounded benign
   probe whose actual Location header is verified to leave the origin;
   a parameter name alone proves nothing. Mixed content from the page's
   own asset list.

## Scoring (deterministic, explained in the report)

- **Risk**: severity-weighted sum over CONFIRMED findings only, with a cap
  rule — any confirmed high-severity finding caps the grade band no matter
  how many minor passes surround it. Fixing cosmetic issues cannot launder
  a dangerous site.
- **Coverage**: checks that reached a verdict (Pass or Finding) divided by
  checks attempted. Inconclusive and Not assessed reduce coverage, never
  raise the score.
- **Confidence**: share of findings backed by direct evidence vs inference
  (e.g., uncertain version detection).
The report shows which findings drive the risk number and the estimated
effect of each fix, labelled an estimate until a rescan verifies it.

## Muse Spark auditor

Three calls maximum per scan (auditor pass; refutation pass, a separate
adversarial call; summary/fix-pack pass), strict output schemas, fixed
evidence inputs per call, timeout + one retry, per-scan cost cap. No
multi-step agent loops anywhere: a call that fails or times out lands in
an explicit failure state (for refutation, "Refutation not run") and is
never silently treated as a pass.

- **Impact and priority**: per finding, how it gets abused on THIS kind of
  site, ordered fix-first list (max 5) with impact/effort reasoning.
- **AI vs engine disagreement**: if the auditor judges a finding overstated,
  the report shows both positions ("Engine: high. Auditor notes: …") and
  keeps the engine's verdict. Nothing is silently discarded.
- **Exploit chains (v2.2)**: the auditor must discover relationships
  between findings, not group nearby findings together. Every chain is
  labelled "AI-derived attack path" and classified exactly one of:
  **Supported** (every required precondition is observed in evidence),
  **Conditional** (at least one precondition is inferred or plausible
  but not observed; renders visually distinct on the graph, dashed, and
  is never presented as a confirmed exploit), or **Unproven** (a required
  precondition is absent or unsupported; not rendered as a path at all,
  recorded in Technical mode only as rejected reasoning, with the reason).
  Every node references one or more existing evidence IDs; every edge
  carries a model explanation plus its supporting evidence IDs. The
  server validates all IDs AND checks the claimed relationship against
  per-chain-type requirements defined in code (which evidence types a
  chain of this type needs before it may be called Supported).
  Corrected example: a CORS chain to cross-origin data exposure requires
  evidence that an untrusted origin is allowed or reflected, that
  credentials are allowed, and that a sensitive response is readable
  cross-origin. Cookie flags alone do not prove session theft: HttpOnly
  governs script access to a cookie and Secure governs its transport,
  and neither by itself establishes cross-origin data access. Chains
  never create findings and never change a severity or the
  deterministic risk score.
- **Refutation pass (v2.2)**: a SEPARATE adversarial call, given only
  the finding claim and the stored evidence (never the auditor's own
  reasoning, so it cannot anchor on it), argues the strongest plausible
  false-positive case. A deterministic evidence assessment stage then
  evaluates both arguments against the original evidence and the
  finding's required preconditions. Scope: high severity findings, plus
  any finding used as a node in a Supported chain. The report shows four
  fields per challenged finding: original claim, counterargument,
  evidence assessment, outcome. Outcomes are exactly three:
  **Survived refutation** (the evidence still supports the finding),
  **Confidence reduced** (the finding remains plausible but a stated
  limitation weakens the conclusion; the Confidence score drops, the
  observation and severity stand), **Not substantiated** (the evidence
  assessment shows a required precondition is absent; the observation
  stays in the report, the interpretive claim is marked not
  substantiated and stops driving the Risk score, and nothing is
  silently deleted). The boundary that keeps this honest: the engine
  establishes what was observed, refutation evaluates the
  interpretation. A model argument alone can at most reduce confidence;
  only the deterministic evidence assessment can mark a claim not
  substantiated, because real-world exploitability is not a question a
  checklist automatically settles either.
- **Counterfactuals**: "fixing X would move risk by ~Y" — always labelled
  an estimate; only a rescan can mark it verified.
- **Fix packs**: per detected stack (generic, nginx, Apache, WordPress,
  Next.js), the snippet, exactly where it goes, and a safe manual
  verification step. Marked untested until a rescan verifies.
- **Auditor evaluation suite**: fixture cases the pipeline must survive —
  fabricated evidence the report validator must reject, unsupported
  severity claims, inconsistent rankings, a fabricated exploit chain link
  the validator must reject, and a refutation argument that tries to
  talk the engine out of a confirmed finding. The refutation suite also
  runs against deliberately ambiguous responses and known false
  positives, and records two numbers: precision gained and true findings
  retained. Refutation must never suppress a true finding on the
  positive fixtures. Run before demo day and after any prompt or model
  change; groundedness and refutation results noted in HACKATHON.md.

## The canvas: an evidence graph, not a card wall

Layers: **Assets** (host, TLS, DNS, pages, libraries) → **Observations**
(raw evidence) → **Findings** → **Fixes**. Clicking a finding highlights its
trace down to the exact response headers, DNS answer, or certificate fields
that support it. A validated exploit chain highlights as one connected path
across the graph. Two presentations of the same data: **Owner mode** (what
it means, what to do, in plain language) and **Technical mode** (request
metadata, headers, CVE references, reproducibility stamp).

**Scan diff + fix verification (P1, demo-critical):** rescan stores a new
scan; diff view shows new / resolved / unchanged / severity-changed /
could-not-repeat. Fix verification reruns only the relevant check group and
labels the finding Resolved, Still present, or Inconclusive based on the
new evidence.

## Judge mode and report exports (v2.2, locked)

Judge mode is the first thing a judge sees. First screen: the name, the
line "See the auditor reason, not just scan", and two entry points:
**Run the seeded demo** (recommended) and **Explore sample reports**.

- **Seeded demo**: one button, fixed target. Judge mode has NO URL input
  at all, so it can never be pointed at a third-party site; arbitrary
  URLs only ever enter through the normal flow with its authorization
  checks. The seeded target is ours and allowlisted for the full check
  set, for that exact host only. No attestation or DNS step stands
  between the judge and the scan.
- **No dead air**: progress streams by check group with honest status
  labels (Queued / Running / Pass / Finding / Inconclusive), and the
  canvas builds live, node by node, as each group lands. No fake
  progress bars, no spinner followed by a finished dashboard.
- **No fake AI**: the seeded live demo calls Muse Spark for its actual
  reasoning during the run. Sample reports are precomputed results and
  are labelled "Saved result" wherever they appear, with scan timestamp,
  scanner version, and model ID, so a historical result can never be
  mistaken for a fresh scan.
- **Preloaded real reports**: generated by real scans of our own sites
  (nyktos.tech, cliphaus.dev), run by us against sites we own and may
  scan, provenance shown per the labelling rule above. They are scanner
  output, never hand assembled. Publishing our own sites' reports is a
  deliberate exception to the private by default rule, which still
  governs every user target.
- **`auditcanvas-evidence.json`**: redacted observations, evidence IDs,
  check outcomes, timestamps, scanner version, and source metadata,
  exactly as stored, plus the scoring inputs and reproducibility stamp.
  The JSON schema is versioned (a schema version field in every bundle)
  and the report and README document how evidence references validate:
  every finding ID resolves to its evidence IDs inside the bundle, so
  the artifact is independently inspectable without trusting the UI.
- **`auditcanvas-fix-pack.zip`**: remediation snippets, affected
  components, applicable conditions, instructions, and verification
  steps. Each fix file carries a header with its finding ID and
  evidence IDs, states which stack and conditions it applies to and
  exactly where it belongs, and is labelled a suggested patch, not an
  automatically safe production change. Only files applicable to the
  detected stack are generated; an nginx config is never produced for a
  Next.js deployment without an explanation of where it would belong.
  Files stay marked untested until a rescan verifies the fix.
- **Third artifact, only if time allows**: a standalone HTML report with
  the evidence graph and the redacted evidence embedded. It ships only
  after the two downloads above are solid.

## Data rules

- Evidence is snippets, not bodies: headers, status lines, cert fields, DNS
  answers, and at most small capped excerpts needed to prove a signature.
- Redaction before storage AND before any model call: Authorization and
  Cookie values, token-like query parameters, and anything matching
  secret patterns. Set-Cookie is stored as attribute flags, never values.
- Reports: cryptographically random IDs, noindex, rate-limited access,
  private by default, 7-day expiry, one-click delete.

## Ownership verification (one method, done properly)

DNS TXT challenge: token bound to the exact hostname, short-lived, and
valid only for that host (a parent-domain verification never authorizes
subdomains or other ports automatically). Verified targets unlock the full
check set; unverified targets always run the restricted passive policy,
attestation checkbox or not.

## Demo target and test fixtures

Seeded vulnerable site (ours, hosted by us) with a planted list, PLUS a
fixture suite so the demo proves accuracy instead of claiming it:
- **Positive fixtures**: every planted flaw must be detected.
- **Negative fixture**: a hardened page that must yield zero findings.
- **Malformed/timeout fixtures**: garbage responses and a hanging endpoint
  must yield Inconclusive, never Pass.
- A verification script runs the suite; it must be green before the demo
  is recorded and before submission day.

## Demo video (3 minutes)

1. Start from Judge mode: one click scans the seeded site; open one
   finding on the graph and show its raw evidence, then follow one
   exploit chain across the graph and show its refutation outcome.
2. Show the auditor layer earning its place: one ambiguous candidate the
   pipeline refuses to call (soft-404 → Inconclusive), straight from the
   fixture suite.
3. Fix cookie attributes and CORS on the demo site, live.
4. Rescan: diff view, before/after evidence, resolved labels, recalculated
   risk with coverage and confidence shown.
5. One deliberately inconclusive check, named as such: this tool would
   rather say "could not verify" than print a clean lie.
6. Close on the promise: real evidence in, verified remediation out.
Prerecorded verified run kept as fallback; the judged demo uses genuine
Muse Spark output.

## 9-day plan

- **Day 0-1 (Oct 26-27)**: Arz's taps (rules, key, credits with the $150
  spend-limit alert). Repo public, API access verified (exact model ID +
  structured outputs on his account, not assumed), evidence schema with
  four-state outcomes, first working Muse Spark call, HACKATHON.md.
- **Day 2-3**: scanner scope FROZEN at the eight groups, built with
  fixtures (incl. soft-404 baseline, DNS error taxonomy); SSRF-safe fetch
  layer (resolve/validate/pin/redirect rules); rate budgets, quotas,
  cooldowns; seeded vulnerable target built.
- **Day 4**: attack-chain reasoning + refutation pass, both behind the
  evidence validator, with the engine-only fallback report intact. This
  is the schedule's main risk day and it is bounded on purpose: three
  model calls maximum, strict output schemas, fixed evidence inputs,
  explicit failure states, no agent loops.
- **Day 5**: canvas rendering (evidence graph, chain paths, owner and
  technical modes), deterministic scoring display, Judge mode entry
  point with live streamed progress, report presentation.
- **Day 6**: live demo stability: full fixture suite green, known-finding
  assertions on the seeded target, chain and refutation test suites
  (incl. ambiguous and known false-positive fixtures).
- **Day 7**: evidence JSON + fix-pack zip downloads; remediation and
  rescan workflow (fix, diff, fix verification); dry runs against our
  own sites (nyktos.tech, cliphaus.dev) generate the preloaded reports.
- **Day 8**: recorded demo video, documentation (README, HACKATHON.md),
  sample-report verification (labels, timestamps, versions rechecked
  against the actual scan records), submission draft.
- **Day 9 (Nov 4)**: final regression test, deployment check, submission
  buffer. SUBMIT (evening Dhaka).

## Priority order

- **P0**: SSRF-safe fetch + authorization enforcement; evidence schema with
  four-state outcomes; eight scanner groups with regression fixtures;
  Muse Spark auditor + report validator; canvas + explainable score;
  seeded target + fix/rescan flow; exploit chains (validator checked,
  classified supported / conditional / unproven); refutation pass
  (separate adversarial call, three outcomes); Judge mode (one-click
  demo scan, live canvas build).
- **P1** (locked, not stretch): `auditcanvas-evidence.json` download;
  `auditcanvas-fix-pack.zip` download; scan diff + fix verification;
  preloaded real reports for Judge mode, labelled Saved result.
- **P2, only if time allows**: standalone HTML report with embedded
  evidence graph; owner/technical mode polish, visual refinement.

## Explicitly out of the 9-day build

No new scanner categories beyond the frozen eight groups. Scheduled
scans and alerts; accounts/teams/permissions; GitHub PR remediation;
multi-domain inventories; authenticated scanning; full SBOM;
continuous monitoring. (Verification stays ONE method: DNS TXT.)

## Rules facts

Dates, the $150 credit, and the banned list in this spec come from the
official rules, FAQ, and resources posts Arz received from the organizers
(Oct 26). The one technical unknown, model ID + structured-output support
on his account, is a Night 0 verification, not an assumption.

---

## Addendum (2026-10-29, post-v2.2): Gemini dev fallback + finalize hardening

Two implementation additions that do not change the locked v2.2 scope:

- **Bundle signing (sweep fixes H1/H2/M4).** Step bundles are
  HMAC-signed by the server (`BUNDLE_SIGNING_SECRET`) and verified at
  assembly/finalize and in the download routes before any contents
  are trusted; `/finalize` is metered per IP and finalized reports
  are cached by the verified bundle-set digest, so the three-call
  cap holds per bundle-set. Bare client-supplied reports posted to
  the download routes get recomputed scores, a re-derived stamp, and
  an explicit client-supplied-unverified integrity label — never the
  server path's `integrity.ok`.
- **Gemini fallback adapter.** `AUDITOR_PROVIDER=gemini` (server env
  only) routes the auditor/refutation transports to Gemini
  (`GEMINI_API_KEY`, `GEMINI_MODEL` default `gemini-3.8-flash`,
  capacity fallback `gemini-3.5-flash-lite`) behind the same call
  contract and the same validators. It exists to prove the model
  layer against a live model before the Meta key verification and as
  an emergency fallback at verification time. **Meta (Muse Spark)
  remains the submission provider, and the public demo runs Meta.**
  The report stamp records the provider and the model that actually
  answered, whichever is active.

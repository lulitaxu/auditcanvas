# AuditCanvas — demo video run-of-show (3:00)

_Recording script for the required hackathon demo video. Built around
the Judge-mode line: **"See the auditor reason, not just scan."**
Total runtime 3:00. One narrator, screen capture of the deployed app
(or a local production instance — see the checklist), no slides._

**The honesty rule for this recording:** narrate only what is on
screen. The auditor's chain classification and refutation outcomes are
produced live by the model and the deterministic assessment; they are
rehearsed, not scripted into existence. Each affected segment below
carries a primary line and a variant line. Use the line that matches
the screen. If neither matches, re-record — never describe an outcome
that is not visible. A prerecorded verified run is kept as fallback
footage, per the spec, and is labelled as such if used.

---

## Pre-recording checklist

Do all of these, in order, before the first take:

- [ ] **Fixtures green.** `npm run verify` prints **73/73 assertions
  passed** on the exact build being recorded. (Must also be green
  again on submission day.)
- [ ] **Key in env.** `META_API_KEY` and `META_MODEL_ID` are set in
  the recording environment (deployment env or local `.env.local` —
  never in the repo, never on screen). A rehearsal scan's report shows
  the auditor status as configured/ok, **not** `engine-only`. This is
  also the first live-model verification: confirm the model ID in the
  report's reproducibility stamp is the account's real one.
- [ ] **Demo target allowlisted.** `AUDITCANVAS_DEMO_HOSTS` includes
  the recording host (default `localhost,127.0.0.1` covers a local
  recording; a deployed recording needs the deployed hostname added
  server-side). One full Judge-mode demo run completes end to end in
  rehearsal — all nine groups land, report finalizes.
- [ ] **Chains + refutation rehearsed.** In rehearsal, note which
  chain the seeded demo produces (Supported or Conditional) and the
  refutation outcome on the challenged finding. Pick the matching
  narration lines in segments 3. If refutation shows "not run", the
  key is not actually wired — stop and fix, do not record.
- [ ] **Fix-and-rescan rig ready** (for segment 4): fixtures running
  standalone (`npm run fixtures`, with the port privilege the README
  describes), fixture control answering at
  `http://127.0.0.1:8911/state`, and one full rehearsal of
  scan → flip (`/flip`) → rescan → diff completed. After rehearsal,
  hit `/reset` so the recorded take starts vulnerable.
- [ ] **Samples state known.** If `scripts/generate-samples.mjs` has
  been run post-deploy, the sample cards show real Saved results; if
  not, the slot shows its placeholder. Segment 1's line works either
  way — do not open the samples slot on camera unless the real cards
  are there.
- [ ] **Stage hygiene.** Browser at 100% zoom, bookmarks bar hidden,
  notifications off, no env files or terminals with secrets visible,
  app already open on Judge mode. A fallback copy of one complete
  verified rehearsal recording is saved before the takes begin.

---

## The run-of-show

### 0:00–0:20 — Problem + promise

**On screen:** Judge mode first screen, untouched. The wordmark, the
line "See the auditor reason, not just scan", the two entry points.

**Narration:**
> "Every security scanner hands you a list and walks away. Half of it
> is noise, none of it shows its proof, and nothing tells you whether
> your fix actually worked. AuditCanvas is built on one rule: the
> scanner decides what exists — the model decides what it means. Real
> evidence in, verified remediation out."

**Action:** at ~0:15, hover — do not click yet — "Run the seeded
demo", then "Explore sample reports", so both entry points register.

### 0:20–1:10 — Live scan of the seeded demo, graph forming

**Action:** click **Run the seeded demo**. Stay on the scan view while
the nine groups stream in (Queued → Running → Pass / Finding /
Inconclusive). As the report lands, scroll the evidence graph into
view and let the Assets → Observations → Findings → Fixes layers
settle.

**Narration:**
> "One click. No URL to type — Judge mode can't be pointed at anyone
> else's site. This target is ours, and it is deliberately
> misconfigured. Nine check groups run for real: headers, TLS,
> cookies, CORS, exposed paths, exposure and secrets, the client
> stack against known CVE ranges, email posture, redirects. Every
> result is stored as evidence — the actual headers, the certificate
> fields, the DNS answers. Watch the canvas build as each group
> lands. Nothing here is a mock-up; this scan is happening now."

**Action:** as the Exposure group lands, rest on its two contrasting
results: the Stripe finding and the Supabase inconclusive next to it.

**Narration:**
> "One more group, the new one: Exposure. It reads the site's own
> JavaScript the way anyone can — and finds a live-format Stripe key
> sitting in a public bundle. The report shows the pattern and a
> fingerprint so the owner can find their key — never the key itself.
> And next to it, an anon key the scanner refuses to call a
> vulnerability, because it can't prove one."

**Action:** at ~0:55, click the exposed-`.env` finding (or the
highest-severity finding on screen). The trace highlights down to its
evidence.

**Narration:**
> "Click any finding and you can walk it down to the exact response
> that proves it. If the evidence isn't there, the finding doesn't
> ship."

### 1:10–1:50 — A chain, and a finding put on trial

**Action:** scroll to the chains block. Move along the rendered chain
path slowly, node by node. Then scroll to the refutation block and
open the challenged finding's four fields: claim, counterargument,
evidence assessment, outcome.

**Narration (chain — use the line that matches the screen):**
> Primary (Supported, solid path): "Findings are bad. Chains are
> worse. Here the auditor connected them into an attack path — and
> the server only lets it render solid because every precondition is
> present in the evidence: the origin is reflected, credentials are
> allowed, and the response is readable cross-origin."
>
> Variant (Conditional, dashed path): "Here the auditor proposed an
> attack path, but one precondition is only inferred, not observed —
> so it renders dashed and is labelled Conditional. It is never
> presented as a confirmed exploit. And a chain whose preconditions
> are absent isn't rendered at all; you'll find it in Technical mode,
> filed as rejected reasoning."

**Narration (refutation — use the line that matches the outcome):**
> Primary (Survived refutation): "Then a second, separate call tries
> to kill the finding. It sees only the claim and the evidence —
> never the first auditor's reasoning, so it can't just agree. It
> argues the strongest false-positive case it can. The deterministic
> evidence assessment judges both sides… and the finding survives.
> The evidence holds."
>
> Variant (Confidence reduced): "…and here the challenge lands a real
> point — a stated limitation in the evidence. The finding stays, the
> severity stays, but the Confidence score drops. A model's argument
> can do that much, and no more."
>
> Variant (Not substantiated): "…and here the assessment finds a
> required precondition is simply absent. The claim is marked Not
> substantiated and stops driving the Risk score. The observation
> stays in the report — nothing is ever silently deleted."

### 1:50–2:30 — Fix pack + rescan diff

**Action:** back on the seeded-demo report, click
**auditcanvas-fix-pack.zip**, open the downloaded archive, and show
one fix file's header (finding ID, evidence IDs, stack, where it
goes). Then cut to the second scan prepared in the checklist: the
vulnerable fixture, scanned through "Scan a site you own", its report
open. Apply the fix: hit the fixture control `/flip` (terminal or a
second tab — the fixture now serves the hardened responses the fix
pack prescribes: headers set, cookies flagged, CORS reflection off).
Return to the report and click **Rescan this target**. Let the steps
stream, and land on the "What changed since the previous scan"
section.

**Narration:**
> "Every finding exports as a fix pack — one suggested patch per
> finding, stamped with the finding and evidence IDs it answers, and
> exactly where it belongs. We applied the fixes to this test site.
> But AuditCanvas doesn't take our word for it. Rescan — and the diff
> is computed from fresh evidence: resolved, new, persistent,
> severity-changed. A finding is only called Resolved when its check
> re-ran to a verdict. Everything that was planted here is now
> Resolved, and the Risk score moved because the evidence moved — not
> because anyone edited a number."

_(If a rehearsal diff shows a different resolved count, narrate the
count on screen. The verify suite's fixture run resolves all 24
planted findings; the in-app take may differ by grouping — the screen
is the script.)_

### 2:30–3:00 — Scoring honesty + close

**Action:** scroll to the scores. Point at Risk, Coverage,
Confidence in turn. Then find one Inconclusive result in the report
(the demo scan's email-posture or TLS row, or switch briefly to
Technical mode) and hover it. End on the full report, graph visible.

**Narration:**
> "Three scores, all deterministic, formulas printed right here —
> the model never touches them. Risk counts confirmed findings only,
> and one confirmed high caps the grade no matter how many small
> passes surround it. Coverage counts only checks that reached a
> verdict. And this — Inconclusive — is the score honesty this tool
> is built on. When AuditCanvas cannot verify something, it says
> 'could not verify'. It would rather tell you that than print a
> clean lie. Real evidence in. Verified remediation out. That's
> AuditCanvas."

**End frame:** the report with the evidence graph and scores visible,
held for two seconds. Cut.

---

## Fallbacks and failure rules

- **Model call fails mid-take:** the report falls back to engine-only
  and says so on screen. That is a designed state, but it is not this
  video — stop, check the key/credits, re-record.
- **A scan step stalls:** budgets and deadlines bound every group; if
  a take still stalls past ~15 seconds on one group, discard the
  take. Do not speed up footage of the scan itself.
- **Outcomes differ from rehearsal:** use the variant lines. If an
  outcome appears that no line covers, that take is a rehearsal now —
  note the outcome, adjust the lines, re-record.
- **Fallback footage:** the prerecorded verified run may replace a
  failed segment only if the submission labels it as a recorded run;
  the primary submission is the live take.

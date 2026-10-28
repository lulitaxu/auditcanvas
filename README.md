# AuditCanvas

Turn real security evidence into verified, understandable remediation.

AuditCanvas scans a website with a deterministic engine (nine check
groups, four outcomes: Pass / Finding / Inconclusive / Not assessed),
stores redacted evidence for every result, and — when configured — has a
Muse Spark auditor explain, prioritize, and adversarially re-check the
findings. The scanner decides what exists; the model decides what it
means. Full design: `SPEC.md` (v2.2). Hackathon notes: `HACKATHON.md`.

## Run it locally

```bash
npm install
cp .env.example .env.local   # optional; without it reports are engine-only
npm run dev                  # http://localhost:3000
```

Judge mode is the first screen: **Run the seeded demo** scans the
deliberately vulnerable target built into this app
(`/api/demo-target`); **Explore sample reports** opens the preloaded
saved results — real scans of our own sites (nyktos.tech,
cliphaus.dev), each labelled "Saved result" with its scan timestamp,
scanner version and model ID. You can also scan your own site —
unverified targets get the restricted passive policy.

The sample reports are generated, not shipped as data: run
`node scripts/generate-samples.mjs` from an environment with ordinary
direct egress (the deployed app's host, or a developer machine) and it
drives this app's own pipeline against both sites, writing a sample
only if the scan genuinely reached its target. Until that post-deploy
run happens, the samples slot shows an explicit "generated after
deploy" placeholder naming both pending targets — the build sandbox
cannot produce them, because its resolver answers these hosts with
reserved 198.18.0.0/15 addresses (which the scanner correctly refuses)
and its network intercepts direct TLS. Details in `HACKATHON.md`
(Day 8 entry) and `src/lib/sample-reports/README.md`.

## Verify the scanner

```bash
npm run verify
```

This boots the fixture servers (vulnerable, hardened, slow, garbage,
and an HTTPS vulnerable origin under a throwaway local CA generated on
the fly) and asserts the scanner's verdicts: expected findings on the
vulnerable targets, **zero** findings on the hardened target, and
Inconclusive (never Pass) on the malformed/timeout targets. It also
covers chain classification (including the spec's corrected CORS
example), refutation outcomes and their effect on the scores, the two
downloads, DNS TXT ownership, and the rescan diff. Current suite:
**73/73 assertions**.

> **Port note:** the scanner, per spec, only speaks ports 80/443, so the
> fixtures bind those ports on distinct loopback addresses
> (127.0.0.1–127.0.0.4, localhost:443). Binding low ports needs root,
> `CAP_NET_BIND_SERVICE`, or `net.ipv4.ip_unprivileged_port_start=0`.
> Run `npm run verify` with sudo on a stock Linux laptop, or set
> `sudo sysctl net.ipv4.ip_unprivileged_port_start=0` first.

`npm run fixtures` starts the same servers standalone (HTTP fixtures on
80, HTTPS on 443 when `AC_CERT_DIR` points at a cert directory). In
standalone mode a loopback control (`http://127.0.0.1:8911/flip`,
`/reset`, `/state`) flips the vulnerable fixture to its hardened
behavior at the same origin — that is what makes the demo video's
fix-and-rescan segment recordable (`DEMO-SCRIPT.md`).

## Configuration

All configuration is via environment variables; `.env.example` is the
template and the only env file in the repo.

| Variable | Meaning |
|---|---|
| `META_API_KEY` | Meta Model API key for the auditor layer. Never committed. |
| `META_MODEL_ID` | Exact model ID on the account. Verified on Night 0 wiring; not assumed in code. |
| `META_API_BASE` | API base URL (default `https://api.meta.ai/v1`). |
| `AUDITCANVAS_DEMO_HOSTS` | Server-side allowlist of demo hostnames that receive the full scan policy (default `localhost,127.0.0.1`). Never settable from a scan request. |
| `BUNDLE_SIGNING_SECRET` | HMAC secret signing scan step bundles; `/finalize` and downloads verify signatures before trusting bundle contents. Set in production before deploying the signing code; unset falls back to an ephemeral per-process secret (signatures then do not survive instance restarts). |
| `AUDITOR_PROVIDER` | Model provider for the auditor layer: `meta` (default) or `gemini`. Server env only, never client-controllable. |
| `GEMINI_API_KEY` | Google Gemini key for the dev stand-in provider. Server-side only; required only when `AUDITOR_PROVIDER=gemini`. |
| `GEMINI_MODEL` | Gemini model for the stand-in (default `gemini-3.8-flash`, capacity fallback `gemini-3.5-flash-lite`). |

**Model providers.** Meta (Muse Spark) is the submission provider and the
only provider the public demo runs: leave `AUDITOR_PROVIDER` unset (or
`meta`). The Gemini adapter exists so the auditor and refutation
prompts, output contracts, and validators can be proven against a live
model before the Meta account verification, and as an emergency
fallback if the Meta endpoint rejects the configured model ID at
verification time. Flip it with `AUDITOR_PROVIDER=gemini` plus
`GEMINI_API_KEY` in the server environment. The adapter is a pure
transport behind the same call contract: all output validation stays
in the existing validator layer, the three-call cap and finalize
metering apply identically, and the report stamp names the provider
and model that actually answered.

Without the Meta variables, scans still complete: the report is the
deterministic engine-only report and carries that status explicitly.

## Architecture

```
app/                     Next.js App Router UI + API routes
  page.js, ScanClient.js   Judge mode (no URL input) + scan-your-own-site flow
  ReportView.js            Evidence graph canvas, owner/technical modes
  api/scan/start|step|[id] Stepwise scan API (one check group per step)
  api/scan/[id]/evidence   auditcanvas-evidence.json (versioned schema)
  api/scan/[id]/fix-pack   auditcanvas-fix-pack.zip (suggested patches)
  api/scan/[id]/rescan|diff Fix-and-rescan lineage + scan diff
  api/samples[/<slug>]     Preloaded Judge-mode sample reports (Saved results)
  api/verify/start|check   DNS TXT ownership challenge
  api/demo-target/         Seeded deliberately-vulnerable demo target
src/lib/
  evidence.js            Evidence schema, stable IDs, redaction, validators
  iputil.js              IPv4/IPv6 block classification (SSRF rules)
  safefetch.js           Pinned-IP fetch: SNI + cert verification, redirect policy
  dnsutil.js             TXT lookups with the spec's DNS error taxonomy
  context.js             Scan policies (full/restricted), budgets, scan context
  scanner/               The eight frozen check groups + exposure (addendum) + registry
  cve-snapshot.json      Versioned CVE snapshot (NVD-verified pull, version in every report stamp)
  scoring.js             Deterministic Risk / Coverage / Confidence
  auditor.js             Muse Spark call sites (max 3/scan), report validator
  chains.js              Exploit chains: server validation + classification
  refutation.js          Adversarial pass + deterministic evidence assessment
  pipeline.js            Finalize: auditor -> chains -> refutation -> rescore
  downloads.js           Evidence bundle + fix-pack generation
  zip.js                 Dependency-free ZIP writer/reader
  ownership.js           DNS TXT challenges + verified-host state
  graph.js               Evidence graph model for the canvas
  report.js              Report assembly + reproducibility stamp
  scanstore.js           In-memory scan sessions, cooldowns, quotas
  samples.js             Sample-report store (reads sample-reports/*.json)
  sample-reports/        Generated Saved-result reports (post-deploy, see above)
fixtures/server.mjs      Vulnerable / hardened / slow / garbage test origins
scripts/verify.mjs       Fixture verification suite (npm run verify)
scripts/verify-admin.mjs Admin suite against a fake Neon adapter (npm run verify:admin)
scripts/generate-samples.mjs  Real scans -> Judge-mode sample reports

app/admin/               Operator console (login, scan console, history, report detail)
app/api/admin/           Admin APIs: login/logout, grant-bound scan start|step|finalize,
                         stored-report downloads (evidence, fix-pack)
src/lib/admin/           Admin storage (dedicated Neon), scrypt password check,
                         durable login backoff, hashed-token sessions, CSRF,
                         scan grants, audit events
db/migrations/           Admin schema (0001_admin.sql)
```

## Operator admin panel

A password-only operator panel at `/admin` (never linked from the
public UI) that can run the full non-destructive check set against
targets that have not completed DNS TXT verification — for the
operator's own properties and authorized engagements. Admin reports
are labeled `origin: 'admin'` / `authorizationState: 'admin'` (never
'verified'), persist in a dedicated Neon database, and are
downloadable only from the stored report. Sessions are server-side,
hashed, and rotating; logins are protected by durable exponential
backoff; every admin step and finalize revalidates the session and
the database-backed scan grant. The full design is the dated
addendum at the end of `SPEC.md`.

**Status: code shipped; activation pending founder steps.** The
panel is inert ("Admin is not configured.") until the founder
creates the Neon database, applies `db/migrations/0001_admin.sql`,
and sets the admin env vars in Vercel — see
[`docs/ADMIN.md`](docs/ADMIN.md). All admin tests run against a
stubbed store (`npm run verify:admin`, 97 assertions); no live-DB
verification has been performed yet, and none is claimed.

## Current state (honest list)

- **Built and verified:** the nine scanner groups, SSRF-safe fetch,
  deterministic scoring, evidence graph canvas with Owner/Technical
  modes, Judge mode, DNS TXT ownership, chains validation +
  classification, refutation with deterministic assessment, both
  downloads, rescan + diff, and the NVD-verified CVE snapshot
  (`nvd-2026-10-28`). Fixture suite 73/73; production build passes.
- **Auditor layer is wired, live-model verification is pending.** All
  three Muse Spark call sites, the report validator, and the
  engine-only fallback are implemented; until `META_API_KEY` /
  `META_MODEL_ID` are set in a deployment and the first real auditor
  call runs, reports carry the explicit `engine-only` status and
  chains/refutation show their not-run states. Nothing in the UI
  pretends the model ran.
- **Sample reports are pending generation** (see "Run it locally"):
  the slot, the API, and the generator are shipped; the reports
  themselves are produced by one post-deploy run of the generator.
- **Summary pass (call 3 of 3) is a call-site stub:** the fix pack is
  generated deterministically and appears in every report; only the
  prose summary waits on the live auditor.
- **Scan sessions are in-memory.** Report persistence, 7-day expiry,
  and one-click delete are the remaining report-lifecycle work.

## Hackathon documents

- `SPEC.md` — the locked design spec (v2.2) plus dated addenda.
- `HACKATHON.md` — build log, including the honest stubs list.
- `SUBMISSION.md` — the cerebralvalley.ai submission draft.
- `DEMO-SCRIPT.md` — the timed 3-minute demo video run-of-show.
- `docs/ADMIN.md` — founder setup sheet for the operator admin panel.

## Safety model (short version)

http/https on ports 80/443 only; every resolved address validated and
the connection pinned to it; private/loopback/link-local/multicast/
reserved and IPv4-mapped addresses rejected; per-hop redirect
re-validation; per-scan budget, timeouts, deadline, and size caps;
non-destructive read-only checks; unverified targets always get the
restricted passive policy. Details in `SPEC.md`.

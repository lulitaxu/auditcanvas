# AuditCanvas

Turn real security evidence into verified, understandable remediation.

AuditCanvas scans a website with a deterministic engine (eight check
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
(`/api/demo-target`); **Explore sample reports** opens the saved-results
space (seeded on Day 7 of the build). You can also scan your own site —
unverified targets get the restricted passive policy.

## Verify the scanner

```bash
npm run verify
```

This boots the fixture servers (vulnerable, hardened, slow, garbage,
and an HTTPS vulnerable origin under a throwaway local CA generated on
the fly) and asserts the scanner's verdicts: expected findings on the
vulnerable targets, **zero** findings on the hardened target, and
Inconclusive (never Pass) on the malformed/timeout targets.

> **Port note:** the scanner, per spec, only speaks ports 80/443, so the
> fixtures bind those ports on distinct loopback addresses
> (127.0.0.1–127.0.0.4, localhost:443). Binding low ports needs root,
> `CAP_NET_BIND_SERVICE`, or `net.ipv4.ip_unprivileged_port_start=0`.
> Run `npm run verify` with sudo on a stock Linux laptop, or set
> `sudo sysctl net.ipv4.ip_unprivileged_port_start=0` first.

`npm run fixtures` starts the same servers standalone (HTTP fixtures on
80, HTTPS on 443 when `AC_CERT_DIR` points at a cert directory).

## Configuration

All configuration is via environment variables; `.env.example` is the
template and the only env file in the repo.

| Variable | Meaning |
|---|---|
| `META_API_KEY` | Meta Model API key for the auditor layer. Never committed. |
| `META_MODEL_ID` | Exact model ID on the account. Verified on Night 0 wiring; not assumed in code. |
| `META_API_BASE` | API base URL (default `https://api.meta.ai/v1`). |
| `AUDITCANVAS_DEMO_HOSTS` | Server-side allowlist of demo hostnames that receive the full scan policy (default `localhost,127.0.0.1`). Never settable from a scan request. |

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
  api/verify/start|check   DNS TXT ownership challenge
  api/demo-target/         Seeded deliberately-vulnerable demo target
src/lib/
  evidence.js            Evidence schema, stable IDs, redaction, validators
  iputil.js              IPv4/IPv6 block classification (SSRF rules)
  safefetch.js           Pinned-IP fetch: SNI + cert verification, redirect policy
  dnsutil.js             TXT lookups with the spec's DNS error taxonomy
  context.js             Scan policies (full/restricted), budgets, scan context
  scanner/               The eight frozen check groups + registry
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
fixtures/server.mjs      Vulnerable / hardened / slow / garbage test origins
scripts/verify.mjs       Fixture verification suite (npm run verify)
```

## Safety model (short version)

http/https on ports 80/443 only; every resolved address validated and
the connection pinned to it; private/loopback/link-local/multicast/
reserved and IPv4-mapped addresses rejected; per-hop redirect
re-validation; per-scan budget, timeouts, deadline, and size caps;
non-destructive read-only checks; unverified targets always get the
restricted passive policy. Details in `SPEC.md`.

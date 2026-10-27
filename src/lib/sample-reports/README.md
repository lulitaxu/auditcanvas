# Preloaded sample reports (Judge mode)

This directory holds the finalized report JSON files that Judge mode's
"Explore sample reports" serves as labelled **Saved results**. One file
per target: `<hostname>.json`, exactly as `finalizeReport` produced it
(results, evidence, scores, reproducibility stamp — never hand edited).

Generate or refresh them with:

```bash
node scripts/generate-samples.mjs
```

That runs the app's own scan pipeline against our own sites
(nyktos.tech, cliphaus.dev) and writes a file **only if the scan
genuinely reached the target** (at least one recorded HTTP response and
at least one check that reached a verdict). It must be run from an
environment with ordinary direct egress — a developer machine or the
deployed app's host — because the scanner connects directly by design
(pinned IPs, no proxy). From the build sandbox it cannot run: that
network's resolver returns reserved 198.18.0.0/15 addresses for these
hosts (which the scanner correctly refuses) and its egress intercepts
direct TLS. See the Day 8 entry in `HACKATHON.md`.

Until the files exist, the Judge-mode samples slot shows an explicit
"generated after deploy" placeholder — never an invented report.

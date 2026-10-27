// Preloaded Judge-mode sample reports (SPEC.md: Judge mode).
//
// Samples are REAL finalized reports produced by scripts/generate-samples.mjs
// against our own sites, stored as JSON in src/lib/sample-reports/ and
// served read-only. They are labelled "Saved result" everywhere they
// appear, with the report's own reproducibility stamp (timestamp,
// scanner version, model ID), so a historical result can never be
// mistaken for a fresh scan. When no sample files exist, the list is
// empty and the UI shows the explicit "generated after deploy"
// placeholder — this module never invents one.
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const SAMPLES_DIR = path.join(process.cwd(), 'src', 'lib', 'sample-reports');
const SLUG_RE = /^[a-z0-9][a-z0-9.-]*$/;

async function readSampleFiles() {
  let names;
  try {
    names = await readdir(SAMPLES_DIR);
  } catch {
    return []; // directory absent → no samples, placeholder state
  }
  const reports = [];
  for (const name of names.filter((n) => n.endsWith('.json')).sort()) {
    try {
      const raw = await readFile(path.join(SAMPLES_DIR, name), 'utf8');
      const report = JSON.parse(raw);
      if (report && report.target && report.stamp) {
        reports.push({ slug: name.replace(/\.json$/, ''), report });
      }
    } catch {
      // A malformed sample file is skipped, never served half-parsed.
    }
  }
  return reports;
}

export function sampleSummary({ slug, report }) {
  return {
    slug,
    label: 'Saved result',
    target: report.target,
    timestamp: report.stamp.timestamp,
    scannerVersion: report.stamp.scannerVersion,
    rulesVersion: report.stamp.rulesVersion,
    modelId: report.stamp.modelId,
    scanPolicy: report.scanPolicy,
    authorizationState: report.authorizationState,
    findings: Array.isArray(report.findings) ? report.findings.length : 0,
    risk: report.scores ? { grade: report.scores.risk.grade, score: report.scores.risk.score } : null,
  };
}

export async function listSamples() {
  const all = await readSampleFiles();
  return all.map(sampleSummary);
}

export async function getSample(slug) {
  if (!SLUG_RE.test(slug || '')) return null;
  const all = await readSampleFiles();
  const hit = all.find((s) => s.slug === slug);
  return hit ? hit.report : null;
}

// The sample slots Judge mode promises, in display order. Used by the
// UI's placeholder state so the pending targets are named, not vague.
export const EXPECTED_SAMPLE_TARGETS = ['https://nyktos.tech', 'https://cliphaus.dev'];

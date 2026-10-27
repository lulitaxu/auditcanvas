// Group 6 — Client stack and CVEs. Library versions are detected from
// the page's own assets, normalized, and matched against affected
// version RANGES in the versioned snapshot. A version inferred from a
// filename or minified bundle is flagged "detection uncertain": it
// lowers Confidence, not severity.
import { makeCheck, redactUrl } from '../evidence.js';
import { getRoot } from './common.js';
import { satisfiesRange } from '../version.js';
import snapshot from '../cve-snapshot.json' with { type: 'json' };

const GROUP = 'stack';
const MAX_ASSETS = 6;

// Detection rules per library. `file` matches a version in the asset
// filename (uncertain), `content` matches a banner inside the file
// (direct observation).
const DETECTORS = [
  { lib: 'jquery', file: /jquery[-.](\d+\.\d+\.\d+)/i, content: /jQuery v(\d+\.\d+\.\d+)/ },
  { lib: 'bootstrap', file: /bootstrap[-.](\d+\.\d+\.\d+)/i, content: /Bootstrap v(\d+\.\d+\.\d+)/ },
  { lib: 'lodash', file: /lodash[-.](\d+\.\d+\.\d+)/i, content: /lodash (?:v)?(\d+\.\d+\.\d+)/i },
  { lib: 'angular', file: /angular[-.](\d+\.\d+\.\d+)/i, content: /AngularJS v(\d+\.\d+\.\d+)/ },
  { lib: 'moment', file: /moment[-.](\d+\.\d+\.\d+)/i, content: /version:\s*(\d+\.\d+\.\d+)/i },
];

function assetUrls(html, baseUrl) {
  const urls = [];
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.protocol === 'http:' || u.protocol === 'https:') urls.push(u.toString());
    } catch {
      /* ignore unparseable src */
    }
  }
  return [...new Set(urls)].slice(0, MAX_ASSETS);
}

export function snapshotStamp() {
  return { snapshotVersion: snapshot.snapshotVersion, source: snapshot.source, generatedAt: snapshot.generatedAt };
}

export function snapshotStale(days = 90) {
  const age = Date.now() - new Date(snapshot.generatedAt).getTime();
  return age > days * 86400000;
}

export async function runStack(ctx) {
  const out = [];
  const snapEv = ctx.evidence.add('cve-snapshot', ctx.base.origin, snapshotStamp());
  let root;
  try {
    root = await getRoot(ctx);
  } catch (err) {
    return [
      {
        checkId: `${GROUP}.fetch`, findingId: null, group: GROUP, outcome: 'inconclusive', severity: null,
        title: 'Landing response could not be fetched',
        detail: `Could not verify: ${err.message}`, evidenceIds: [snapEv], inference: false,
      },
    ];
  }
  const html = root.res.bodyText || '';
  const assets = assetUrls(html, root.res.finalUrl || ctx.url('/'));
  const detections = []; // {lib, version, source, assetUrl, evidenceId}

  // Filename-based detection first (no extra requests).
  for (const asset of assets) {
    for (const d of DETECTORS) {
      const m = asset.match(d.file);
      if (m) detections.push({ lib: d.lib, version: m[1], source: 'filename', assetUrl: asset });
    }
  }

  // Content-based detection for assets not already pinned by filename.
  for (const asset of assets) {
    if (detections.some((x) => x.assetUrl === asset)) continue;
    let body;
    try {
      const res = await ctx.fetch(asset, { sizeCapBytes: 256 * 1024 });
      body = res.bodyText || '';
    } catch {
      continue; // unfetchable asset: filename detection (if any) stands
    }
    for (const d of DETECTORS) {
      const m = body.slice(0, 256 * 1024).match(d.content);
      if (m) detections.push({ lib: d.lib, version: m[1], source: 'content', assetUrl: asset });
    }
  }

  // Dedup: content beats filename for the same library.
  const byLib = new Map();
  for (const det of detections) {
    const prev = byLib.get(det.lib);
    if (!prev || (prev.source === 'filename' && det.source === 'content')) byLib.set(det.lib, det);
  }

  if (byLib.size === 0) {
    out.push(
      makeCheck({
        group: GROUP, check: 'none-detected', outcome: 'pass',
        title: 'No tracked client libraries detected',
        detail: `Scanned ${assets.length} script asset(s) from the landing page; none matched a library in snapshot ${snapshot.snapshotVersion}. Libraries loaded from third-party CDNs are detected by the same rules when reachable.`,
        evidenceIds: [root.evidenceId, snapEv],
      })
    );
    return out;
  }

  let anyFinding = false;
  for (const det of byLib.values()) {
    const detEv = ctx.evidence.add('asset-detection', det.assetUrl, {
      library: det.lib,
      version: det.version,
      detectionSource: det.source,
      asset: redactUrl(det.assetUrl),
    });
    const entries = snapshot.libraries[det.lib] || [];
    const matched = entries.filter((e) => satisfiesRange(det.version, e.affected));
    if (matched.length === 0) {
      out.push(
        makeCheck({
          group: GROUP, check: `${det.lib}-current`, outcome: 'pass',
          title: `${det.lib} ${det.version} is outside every known affected range`,
          detail: `Detected from ${det.source === 'filename' ? 'the asset filename (detection uncertain)' : 'the file banner (direct observation)'}; no CVE range in the snapshot covers this version.`,
          evidenceIds: [detEv, snapEv], inference: det.source === 'filename',
        })
      );
      continue;
    }
    for (const entry of matched) {
      anyFinding = true;
      out.push(
        makeCheck({
          group: GROUP, check: `${det.lib}-${entry.cve.toLowerCase()}`, outcome: 'finding', severity: entry.severity,
          title: `${det.lib} ${det.version} is affected by ${entry.cve}`,
          detail: `${entry.summary} Affected range: ${entry.affected} (snapshot ${snapshot.snapshotVersion}, ${snapshot.source}). Version detected from ${det.source === 'filename' ? 'the asset filename, so detection is uncertain and confidence is reduced; severity is unchanged' : 'the file banner (direct observation)'}.`,
          evidenceIds: [detEv, snapEv], inference: det.source === 'filename',
        })
      );
    }
  }
  void anyFinding;
  return out;
}

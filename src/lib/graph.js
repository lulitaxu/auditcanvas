// Evidence graph model (SPEC.md: "an evidence graph, not a card wall").
// Layers: Assets -> Observations (evidence) -> Findings -> Fixes.
// Pure function of the finalized report, shared by the canvas view.
//
// Chain rendering rules live here too, so they cannot drift:
//  - Supported chains render as solid highlighted paths.
//  - Conditional chains render DASHED, visually distinct, and are
//    never presented as confirmed.
//  - Unproven chains are NOT part of the graph at all — they are
//    returned separately as rejected reasoning for Technical mode.

const LAYERS = ['asset', 'evidence', 'finding', 'fix'];

export function buildGraph(report) {
  const nodes = [];
  const edges = [];
  const seen = new Set();
  const addNode = (n) => {
    if (seen.has(n.id)) return;
    seen.add(n.id);
    nodes.push(n);
  };
  const addEdge = (from, to, kind) => {
    if (from === to) return;
    if (!edges.some((e) => e.from === from && e.to === to && e.kind === kind)) {
      edges.push({ from, to, kind });
    }
  };

  let host = report.target;
  try {
    host = new URL(report.target).host;
  } catch { /* keep raw target */ }
  addNode({ id: 'asset:target', layer: 0, kind: 'asset', line1: host, line2: 'target' });

  for (const e of report.evidence || []) {
    addNode({ id: `ev:${e.id}`, layer: 1, kind: 'evidence', line1: e.id, line2: e.kind });
    addEdge('asset:target', `ev:${e.id}`, 'observes');
  }

  for (const r of report.results || []) {
    if (r.outcome !== 'finding') continue;
    addNode({
      id: `f:${r.findingId}`,
      layer: 2,
      kind: 'finding',
      line1: r.findingId,
      line2: r.refutation ? `${r.severity} · ${r.refutation.outcomeLabel}` : r.severity,
      severity: r.severity,
      title: r.title,
    });
    for (const id of r.evidenceIds || []) addEdge(`ev:${id}`, `f:${r.findingId}`, 'supports');
  }

  const drivers = (report.scores && report.scores.risk && report.scores.risk.drivers) || [];
  for (const d of drivers.slice(0, 5)) {
    addNode({
      id: `fix:${d.findingId}`,
      layer: 3,
      kind: 'fix',
      line1: 'fix',
      line2: d.title.length > 30 ? `${d.title.slice(0, 29)}…` : d.title,
      title: d.title,
    });
    addEdge(`f:${d.findingId}`, `fix:${d.findingId}`, 'fixes');
  }

  // Highlighted chain paths — RENDERED chains only (supported +
  // conditional). A path is the chain's finding nodes in order, plus
  // each node's edge down to its cited evidence.
  const rendered = (report.chains && report.chains.chains) || [];
  const chainPaths = rendered.map((chain) => {
    const nodeIds = (chain.nodes || []).map((n) => `f:${n.findingId}`);
    const pairs = [];
    for (let i = 0; i + 1 < nodeIds.length; i++) pairs.push([nodeIds[i], nodeIds[i + 1]]);
    for (const node of chain.nodes || []) {
      for (const id of node.evidenceIds || []) pairs.push([`ev:${id}`, `f:${node.findingId}`]);
    }
    return {
      id: chain.id,
      title: chain.title,
      classification: chain.classification,
      nodeIds,
      pairs: pairs.map(([a, b]) => `${a}|${b}`),
    };
  });

  return {
    nodes,
    edges,
    chainPaths,
    layers: LAYERS,
    unproven: (report.chains && report.chains.unproven) || [],
  };
}

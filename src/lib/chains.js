// Exploit chains (SPEC.md v2.2) — AI-derived attack paths over the
// evidence graph, validated and classified by the SERVER, never by the
// model that proposed them.
//
// Rules encoded here:
//  - Every chain is labelled "AI-derived attack path".
//  - Classification is exactly one of Supported / Conditional / Unproven,
//    computed in code from per-chain-type evidence requirements (below):
//      Supported   — every required precondition is OBSERVED in evidence.
//      Conditional — no precondition is absent, but at least one is only
//                    INFERRED. Renders dashed, never presented as confirmed.
//      Unproven    — a required precondition is ABSENT or unsupported.
//                    NOT rendered as a path; recorded for Technical mode
//                    only, as rejected reasoning, with the reason.
//  - Every node cites finding IDs and evidence IDs; every edge carries a
//    model explanation plus supporting evidence IDs. Unknown IDs, unknown
//    chain types, or malformed proposals are rejected outright (the
//    `invalid` list), separately from Unproven classification.
//  - Chains never create findings and never change a severity or the
//    deterministic Risk score.
//  - With no model configured there are no proposals, and the result is
//    an explicit not-run state. Chains are never fabricated by the engine.
//
// The corrected CORS example from the spec lives in the catalog below:
// a CORS chain to cross-origin data exposure requires evidence that an
// untrusted origin is allowed or reflected, that credentials are allowed,
// AND that a sensitive response is readable cross-origin. Cookie flags
// satisfy none of these: HttpOnly governs script access to a cookie and
// Secure governs its transport; neither establishes cross-origin access.

export const CHAIN_LABEL = 'AI-derived attack path';
export const CHAIN_CLASSIFICATIONS = Object.freeze(['supported', 'conditional', 'unproven']);

// ---------------------------------------------------------------------------
// Evidence helpers
// ---------------------------------------------------------------------------

function evidenceById(report) {
  return new Map((report.evidence || []).map((e) => [e.id, e]));
}

function findingById(report) {
  return new Map((report.results || []).filter((r) => r.findingId).map((r) => [r.findingId, r]));
}

// The evidence a chain stands on: what its nodes/edges cite, plus the
// evidence of the findings it uses as nodes.
function chainEvidence(report, proposal) {
  const byId = evidenceById(report);
  const findings = findingById(report);
  const ids = new Set();
  for (const node of proposal.nodes || []) {
    for (const id of node.evidenceIds || []) ids.add(id);
    const f = findings.get(node.findingId);
    if (f) for (const id of f.evidenceIds || []) ids.add(id);
  }
  for (const edge of proposal.edges || []) {
    for (const id of edge.evidenceIds || []) ids.add(id);
  }
  return [...ids].map((id) => byId.get(id)).filter(Boolean);
}

function httpResponses(items) {
  return items.filter((e) => e.kind === 'http-response');
}

function targetOrigin(report) {
  try {
    return new URL(report.target).origin;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Chain-type catalog: per-type evidence requirements, in code.
// Each precondition evaluator returns 'observed' | 'inferred' | 'absent'
// and the evidence IDs that support the judgement.
// ---------------------------------------------------------------------------

export const CHAIN_TYPES = {
  'cors-data-exposure': {
    title: 'Cross-origin data exposure via credentialed CORS',
    description:
      'An untrusted origin is allowed or reflected, credentials are allowed, and a sensitive response is readable cross-origin. All three are required; cookie flags prove none of them.',
    preconditions: [
      {
        id: 'untrusted-origin-allowed',
        description: 'An untrusted origin is allowed or reflected in Access-Control-Allow-Origin',
        evaluate(report, items) {
          const carrier = corsCarrierFor(report, items);
          if (carrier) return { state: 'observed', evidenceIds: [carrier.id] };
          const anyCorsFinding = (report.results || []).some((r) => r.group === 'cors' && r.outcome === 'finding');
          return { state: anyCorsFinding ? 'inferred' : 'absent', evidenceIds: [] };
        },
      },
      {
        id: 'credentials-allowed',
        description: 'Access-Control-Allow-Credentials: true accompanies the permissive origin',
        evaluate(report, items) {
          const carrier = corsCarrierFor(report, items);
          if (carrier && (carrier.data.headers || {})['access-control-allow-credentials'] === 'true') {
            return { state: 'observed', evidenceIds: [carrier.id] };
          }
          return { state: 'absent', evidenceIds: carrier ? [carrier.id] : [] };
        },
      },
      {
        id: 'sensitive-response-readable',
        description: 'A sensitive response (session-bearing or JSON API data) is the one readable cross-origin',
        evaluate(report, items) {
          const carrier = corsCarrierFor(report, items);
          if (!carrier) return { state: 'absent', evidenceIds: [] };
          const creds = (carrier.data.headers || {})['access-control-allow-credentials'] === 'true';
          if (!creds) return { state: 'absent', evidenceIds: [carrier.id] };
          const cookies = carrier.data.setCookies || [];
          const ctype = (carrier.data.headers || {})['content-type'] || '';
          if (cookies.length > 0 || ctype.includes('application/json')) {
            return { state: 'observed', evidenceIds: [carrier.id] };
          }
          // The cross-origin read itself is proven; that the readable
          // response is SENSITIVE is not. Inference, not observation.
          return { state: 'inferred', evidenceIds: [carrier.id] };
        },
      },
    ],
  },

  'plaintext-session-exposure': {
    title: 'Session exposure over plaintext transport',
    description:
      'A session cookie can travel unencrypted: the cookie lacks Secure (Secure governs transport) and transport protection (HSTS) is missing or weak on an HTTPS target, or the target is plain HTTP.',
    preconditions: [
      {
        id: 'cookie-observed',
        description: 'The target sets at least one cookie',
        evaluate(report, items) {
          const withCookies = httpResponses(items).filter((e) => (e.data.setCookies || []).length > 0);
          if (withCookies.length) return { state: 'observed', evidenceIds: withCookies.map((e) => e.id) };
          return { state: 'absent', evidenceIds: [] };
        },
      },
      {
        id: 'cookie-may-cross-plaintext',
        description: 'At least one cookie lacks the Secure attribute',
        evaluate(report, items) {
          const insecure = httpResponses(items).filter((e) =>
            (e.data.setCookies || []).some((c) => c.secure === false)
          );
          if (insecure.length) return { state: 'observed', evidenceIds: insecure.map((e) => e.id) };
          return { state: 'absent', evidenceIds: [] };
        },
      },
      {
        id: 'transport-not-enforced',
        description: 'Nothing forces HTTPS: plain-HTTP target, or HSTS missing/weak',
        evaluate(report) {
          const isHttp = typeof report.target === 'string' && report.target.startsWith('http://');
          if (isHttp) return { state: 'observed', evidenceIds: [] };
          const missing = (report.results || []).find((r) => r.findingId === 'f-headers-hsts-missing');
          if (missing) return { state: 'observed', evidenceIds: missing.evidenceIds || [] };
          const weak = (report.results || []).find((r) => r.findingId === 'f-headers-hsts-weak');
          if (weak) return { state: 'inferred', evidenceIds: weak.evidenceIds || [] };
          return { state: 'absent', evidenceIds: [] };
        },
      },
    ],
  },

  'known-vuln-library-exposure': {
    title: 'Known-vulnerable library reachable in the page',
    description:
      'A client library version inside a CVE-affected range is loaded by the page, so the published exploit preconditions hold for any visitor.',
    preconditions: [
      {
        id: 'version-in-affected-range',
        description: 'A stack finding places a detected version inside a CVE-affected range',
        evaluate(report) {
          const cve = (report.results || []).filter(
            (r) => r.group === 'stack' && r.outcome === 'finding' && /cve/i.test(r.findingId || '')
          );
          if (cve.length) return { state: 'observed', evidenceIds: cve.flatMap((r) => r.evidenceIds || []) };
          return { state: 'absent', evidenceIds: [] };
        },
      },
      {
        id: 'library-actually-loaded',
        description: 'The library is actually loaded by the page (asset detection evidence)',
        evaluate(report, items) {
          const det = items.filter((e) => e.kind === 'asset-detection');
          const cve = (report.results || []).find(
            (r) => r.group === 'stack' && r.outcome === 'finding' && /cve/i.test(r.findingId || '')
          );
          if (det.length) {
            // A filename-only detection is inference by the scanner's own
            // accounting (it lowers Confidence there too): the range match
            // is real, the exact version is not directly observed.
            if (cve && cve.inference) return { state: 'inferred', evidenceIds: det.map((e) => e.id) };
            return { state: 'observed', evidenceIds: det.map((e) => e.id) };
          }
          return { state: 'absent', evidenceIds: [] };
        },
      },
    ],
  },
};

// The response that carries the permissive CORS headers, judged against
// the report's own target origin.
function corsCarrierFor(report, items) {
  const origin = targetOrigin(report);
  return httpResponses(items).find((e) => {
    const acao = (e.data.headers || {})['access-control-allow-origin'];
    if (!acao) return false;
    if (acao === '*') return true;
    try {
      const u = new URL(acao);
      return !origin || u.origin !== origin;
    } catch {
      return false;
    }
  });
}

// ---------------------------------------------------------------------------
// Validation + classification
// ---------------------------------------------------------------------------

// Structural validation (hard reject): shape, known type, every cited
// finding/evidence ID resolves inside this report. Returns a list of
// problems; empty means structurally acceptable.
export function validateChainProposal(proposal, report) {
  const problems = [];
  if (!proposal || typeof proposal !== 'object') return ['proposal is not an object'];
  if (!CHAIN_TYPES[proposal.type]) problems.push(`unknown chain type: ${proposal.type}`);
  if (typeof proposal.title !== 'string' || !proposal.title) problems.push('title is required');
  const findings = findingById(report);
  const evidence = evidenceById(report);
  const nodes = Array.isArray(proposal.nodes) ? proposal.nodes : [];
  if (!nodes.length) problems.push('chain has no nodes');
  const nodeFindings = new Set();
  for (const node of nodes) {
    if (!node || !findings.has(node.findingId)) {
      problems.push(`unknown findingId in chain node: ${node && node.findingId}`);
      continue;
    }
    nodeFindings.add(node.findingId);
    for (const id of node.evidenceIds || []) {
      if (!evidence.has(id)) problems.push(`unknown evidenceId in chain node (${node.findingId}): ${id}`);
    }
  }
  for (const edge of Array.isArray(proposal.edges) ? proposal.edges : []) {
    if (!edge || !nodeFindings.has(edge.from) || !nodeFindings.has(edge.to)) {
      problems.push(`chain edge references a finding that is not a node: ${edge && edge.from} -> ${edge && edge.to}`);
    }
    if (!edge || typeof edge.explanation !== 'string' || !edge.explanation) {
      problems.push('chain edge is missing its explanation');
    }
    for (const id of (edge && edge.evidenceIds) || []) {
      if (!evidence.has(id)) problems.push(`unknown evidenceId in chain edge: ${id}`);
    }
  }
  return problems;
}

// Deterministic classification: evaluate the type's preconditions
// against the stored evidence. The model's claimed classification is
// never consulted here.
export function classifyChain(proposal, report) {
  const def = CHAIN_TYPES[proposal.type];
  const items = chainEvidence(report, proposal);
  const preconditions = def.preconditions.map((p) => {
    const r = p.evaluate(report, items);
    return { id: p.id, description: p.description, state: r.state, evidenceIds: r.evidenceIds || [] };
  });
  let classification = 'supported';
  if (preconditions.some((p) => p.state === 'absent')) classification = 'unproven';
  else if (preconditions.some((p) => p.state === 'inferred')) classification = 'conditional';
  const absent = preconditions.filter((p) => p.state === 'absent');
  const reason =
    classification === 'unproven'
      ? `Required precondition absent: ${absent.map((p) => p.id).join(', ')}.`
      : classification === 'conditional'
        ? `Precondition(s) inferred, not observed: ${preconditions
            .filter((p) => p.state === 'inferred')
            .map((p) => p.id)
            .join(', ')}.`
        : 'Every required precondition is observed in the stored evidence.';
  return { classification, preconditions, reason };
}

// Turn model proposals into the report's chains block:
//  { status, chains: [rendered: supported + conditional],
//    unproven: [rejected reasoning, Technical mode only],
//    invalid: [structurally rejected proposals, with problems] }
// `chains` is the ONLY list the graph renders as paths.
export function buildChains(proposals, report) {
  const rendered = [];
  const unproven = [];
  const invalid = [];
  let n = 0;
  for (const proposal of Array.isArray(proposals) ? proposals : []) {
    n += 1;
    const problems = validateChainProposal(proposal, report);
    if (problems.length) {
      invalid.push({ proposal, problems });
      continue;
    }
    const { classification, preconditions, reason } = classifyChain(proposal, report);
    const chain = {
      id: `chain-${n}`,
      type: proposal.type,
      title: proposal.title,
      label: CHAIN_LABEL,
      classification,
      claimedClassification: proposal.claimedClassification || null,
      nodes: proposal.nodes,
      edges: Array.isArray(proposal.edges) ? proposal.edges : [],
      preconditions,
      reason,
    };
    if (classification === 'unproven') unproven.push(chain);
    else rendered.push(chain);
  }
  return { status: 'ok', chains: rendered, unproven, invalid };
}

// Entry point used by the pipeline. Chain derivation is part of the
// auditor pass (call 1 of the max 3): proposals arrive inside the
// auditor output. Without a configured model there are no proposals and
// the state is explicit — the engine never invents chains.
export function deriveChains(report, auditorOutput, config) {
  if (!config || !config.configured) {
    return {
      status: 'not-run',
      reason:
        config.provider === 'gemini'
          ? 'Chain derivation is part of the auditor pass, which is not configured (AUDITOR_PROVIDER=gemini but GEMINI_API_KEY unset). No chains are shown; the engine never fabricates them.'
          : 'Chain derivation is part of the Muse Spark auditor pass, which is not configured (META_API_KEY / META_MODEL_ID unset). No chains are shown; the engine never fabricates them.',
      chains: [],
      unproven: [],
      invalid: [],
    };
  }
  if (!auditorOutput) {
    return {
      status: 'not-run',
      reason: 'The auditor pass produced no output, so no chain proposals exist to validate.',
      chains: [],
      unproven: [],
      invalid: [],
    };
  }
  return buildChains(auditorOutput.chains || [], report);
}

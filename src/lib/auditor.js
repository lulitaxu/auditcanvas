// Muse Spark auditor layer — call sites and contracts (SPEC.md stage 3).
//
// NIGHT 0 STATE: no real API key is wired in this environment. Every
// pass below checks the env config first and returns an explicit
// not-configured status, and the report falls back to the engine-only
// deterministic report. A failed or missing call is a visible state,
// never a silent pass.
//
// Hard rules encoded here:
//  - Model ID and key come from env (META_MODEL_ID / META_API_KEY). The
//    exact ID and structured-output support on Arz's account are a
//    Night 0 verification, not an assumption (SPEC.md).
//  - Maximum THREE model calls per scan: auditor, refutation, summary.
//    No agent loops anywhere.
//  - The model may explain, rank and dispute; it may not create, delete
//    or silently downgrade a finding. Its output passes the report
//    validator before anything is shown.
export const MAX_MODEL_CALLS_PER_SCAN = 3;

export function auditorConfig(env = process.env) {
  const apiKey = env.META_API_KEY || '';
  const modelId = env.META_MODEL_ID || '';
  return {
    configured: Boolean(apiKey && modelId),
    modelId: modelId || null,
    apiBase: env.META_API_BASE || 'https://api.meta.ai/v1',
    apiKeyPresent: Boolean(apiKey),
  };
}

// One bounded model call: timeout, one retry, JSON expected. Written
// against a chat-completions shape with a JSON-parse fallback; the exact
// endpoint/response_format support must be verified against the account
// on Night 0 before this is exercised live (see HACKATHON.md).
async function callModel(config, { system, user }, { timeoutMs = 20000 } = {}) {
  const { default: fetchFn } = { default: globalThis.fetch };
  let lastErr = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetchFn(`${config.apiBase}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${process.env.META_API_KEY}`,
        },
        body: JSON.stringify({
          model: config.modelId,
          messages: [
            { role: 'system', content: system },
            { role: 'user', content: user },
          ],
          response_format: { type: 'json_object' },
        }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`Model API HTTP ${res.status}`);
      const body = await res.json();
      const text = body && body.choices && body.choices[0] && body.choices[0].message && body.choices[0].message.content;
      if (typeof text !== 'string') throw new Error('Model response has no message content');
      try {
        return JSON.parse(text);
      } catch {
        const m = text.match(/\{[\s\S]*\}/);
        if (!m) throw new Error('Model response is not JSON');
        return JSON.parse(m[0]);
      }
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('Model call failed');
}

// Report validator (SPEC stage 4) for auditor output: rejects any note
// that references an unknown finding or evidence ID, or quotes text that
// is not present verbatim in the stored evidence.
export function validateAuditorOutput(output, report) {
  const errors = [];
  if (!output || typeof output !== 'object') return { ok: false, errors: ['output is not an object'] };
  const findingIds = new Set(report.results.filter((r) => r.findingId).map((r) => r.findingId));
  const evidenceById = new Map(report.evidence.map((e) => [e.id, JSON.stringify(e.data)]));
  const notes = Array.isArray(output.findingNotes) ? output.findingNotes : [];
  for (const note of notes) {
    if (!findingIds.has(note.findingId)) errors.push(`unknown findingId: ${note.findingId}`);
    for (const id of note.evidenceIds || []) {
      if (!evidenceById.has(id)) errors.push(`unknown evidenceId: ${id}`);
    }
    if (note.quote) {
      const haystack = (note.evidenceIds || []).map((id) => evidenceById.get(id) || '').join('\n');
      if (!haystack.includes(note.quote)) errors.push(`quote not present verbatim in evidence for ${note.findingId}`);
    }
  }
  return { ok: errors.length === 0, errors };
}

const NOT_CONFIGURED = {
  status: 'not-configured',
  reason: 'META_API_KEY / META_MODEL_ID are not set; report is engine-only (deterministic).',
};

// Pass 1 of 3: impact, prioritization, explanations, fix drafts.
export async function auditorPass(report, config = auditorConfig()) {
  if (!config.configured) return { ...NOT_CONFIGURED, pass: 'auditor' };
  try {
    const output = await callModel(config, {
      system:
        'You are the AuditCanvas auditor. You receive deterministic scanner findings with evidence IDs. Explain impact and prioritize. You may not create, delete, or downgrade findings. Reference only the evidence IDs given.',
      user: JSON.stringify({
        findings: report.results.filter((r) => r.outcome === 'finding'),
        evidence: report.evidence,
      }),
    });
    const verdict = validateAuditorOutput(output, report);
    if (!verdict.ok) return { status: 'rejected', pass: 'auditor', errors: verdict.errors };
    return { status: 'ok', pass: 'auditor', output };
  } catch (err) {
    return { status: 'failed', pass: 'auditor', reason: String(err && err.message ? err.message : err) };
  }
}

// Pass 2 of 3: refutation — a separate adversarial call that sees only
// the claim and the stored evidence, never the auditor's reasoning.
export async function refutationPass(report, config = auditorConfig()) {
  if (!config.configured) return { status: 'not-run', pass: 'refutation', reason: NOT_CONFIGURED.reason };
  // The deterministic evidence assessment that consumes the counterargument
  // lands with the Day 4 build; the call site and its failure state are
  // fixed now so nothing downstream has to change shape.
  return { status: 'not-run', pass: 'refutation', reason: 'Refutation wiring lands on Day 4 (spec plan); call site reserved.' };
}

// Pass 3 of 3: summary + fix pack drafting.
export async function summaryPass(report, config = auditorConfig()) {
  if (!config.configured) return { ...NOT_CONFIGURED, pass: 'summary' };
  return { status: 'not-run', pass: 'summary', reason: 'Summary/fix-pack wiring lands after the auditor pass (Day 4-7); call site reserved.' };
}

// Orchestrator: at most MAX_MODEL_CALLS_PER_SCAN calls, in order, and
// the report always survives without the API.
export async function annotateReport(report) {
  const config = auditorConfig();
  if (!config.configured) {
    return {
      status: 'engine-only',
      modelId: null,
      reason: NOT_CONFIGURED.reason,
      calls: [],
    };
  }
  const calls = [];
  calls.push(await auditorPass(report, config));
  if (calls.length < MAX_MODEL_CALLS_PER_SCAN) calls.push(await refutationPass(report, config));
  if (calls.length < MAX_MODEL_CALLS_PER_SCAN) calls.push(await summaryPass(report, config));
  return { status: 'annotated', modelId: config.modelId, calls };
}

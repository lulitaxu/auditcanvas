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
//  - Provider selection is env-only (AUDITOR_PROVIDER): Meta is the
//    default and the submission provider; 'gemini' selects the dev
//    stand-in transport in gemini.js behind this same call contract.
//  - Maximum THREE model calls per scan: auditor, refutation, summary.
//    No agent loops anywhere.
//  - The model may explain, rank and dispute; it may not create, delete
//    or silently downgrade a finding. Its output passes the report
//    validator before anything is shown.
import { geminiConfig, callGemini } from './gemini.js';

export const MAX_MODEL_CALLS_PER_SCAN = 3;

// Provider selection is by server env ONLY: AUDITOR_PROVIDER=gemini
// selects the Gemini dev stand-in (gemini.js); anything else —
// including unset — selects Meta (Muse Spark), the submission
// provider. Never client-controllable. The returned config carries
// the provider so the report stamp can state honestly which provider
// and model actually produced the annotations.
export function auditorProvider(env = process.env) {
  return env.AUDITOR_PROVIDER === 'gemini' ? 'gemini' : 'meta';
}

export function auditorConfig(env = process.env) {
  if (auditorProvider(env) === 'gemini') return geminiConfig(env);
  const apiKey = env.META_API_KEY || '';
  const modelId = env.META_MODEL_ID || '';
  return {
    provider: 'meta',
    configured: Boolean(apiKey && modelId),
    modelId: modelId || null,
    apiBase: env.META_API_BASE || 'https://api.meta.ai/v1',
    apiKeyPresent: Boolean(apiKey),
  };
}

export function notConfiguredReason(config) {
  return config && config.provider === 'gemini'
    ? 'AUDITOR_PROVIDER=gemini but GEMINI_API_KEY is not set; report is engine-only (deterministic).'
    : 'META_API_KEY / META_MODEL_ID are not set; report is engine-only (deterministic).';
}

// One bounded model call: timeout, one retry, JSON expected. Written
// against a chat-completions shape with a JSON-parse fallback; the exact
// endpoint/response_format support must be verified against the account
// on Night 0 before this is exercised live (see HACKATHON.md).
//
// Dispatch: a gemini-provider config goes to the Gemini transport
// (gemini.js, same call contract); everything else takes the Meta
// path below. The pipeline's call sites and the 3-call cap are
// provider-agnostic — the cap lives in pipeline.js, not in either
// transport.
export async function callModel(config, payload, opts = {}) {
  if (config && config.provider === 'gemini') return callGemini(config, payload, opts);
  const { system, user } = payload;
  const { timeoutMs = 20000 } = opts;
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

function notConfigured(config, pass) {
  return { status: 'not-configured', pass, reason: notConfiguredReason(config) };
}

// Pass 1 of 3: impact, prioritization, explanations, fix drafts — and
// exploit-chain proposals. Chain proposals are NOT trusted: chains.js
// validates every ID and re-derives the classification from per-chain-type
// evidence requirements in code; the model's claimed classification is
// recorded but never used.
export async function auditorPass(report, config = auditorConfig()) {
  if (!config.configured) return notConfigured(config, 'auditor');
  try {
    const output = await callModel(config, {
      system:
        'You are the AuditCanvas auditor. You receive deterministic scanner findings with evidence IDs. Explain impact and prioritize. You may not create, delete, or downgrade findings. Reference only the evidence IDs given. You may also propose exploit chains: relationships BETWEEN findings where one finding\'s evidence enables the next. Each chain proposal needs a type from the provided catalog, nodes citing finding IDs and evidence IDs, edges with explanations, and your claimed classification (supported / conditional / unproven). Cookie flags alone never prove session theft: HttpOnly governs script access to a cookie, Secure governs its transport.',
      user: JSON.stringify({
        findings: report.results.filter((r) => r.outcome === 'finding'),
        evidence: report.evidence,
        chainTypes: ['cors-data-exposure', 'plaintext-session-exposure', 'known-vuln-library-exposure'],
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
// The implementation lives in refutation.js (deterministic evidence
// assessment included); this wrapper exists so the three call sites
// stay visible in one file. Imported dynamically to avoid a module
// cycle (refutation.js uses callModel from here).
export async function refutationPass(report, chainsResult, config = auditorConfig()) {
  const { runRefutation } = await import('./refutation.js');
  return runRefutation(report, chainsResult, config);
}

// Pass 3 of 3: summary + fix pack drafting. The fix pack itself is
// generated deterministically (downloads.js) so it exists in every
// report, engine-only included; this pass only drafts prose summary.
export async function summaryPass(report, config = auditorConfig()) {
  if (!config.configured) return notConfigured(config, 'summary');
  return { status: 'not-run', pass: 'summary', reason: 'Summary drafting lands after the auditor pass is verified live; the deterministic fix pack (downloads) does not depend on it.' };
}

// Gemini transport for the auditor layer — DEV STAND-IN ONLY.
//
// Purpose (2026-10-29): let the auditor + refutation prompts and
// output contracts be proven against a live model before the Meta
// account verification completes, and serve as an emergency fallback
// if the Meta endpoint rejects the configured model ID at that
// verification. It is NOT the submission path: Meta (Muse Spark)
// remains the default provider and the only provider the public demo
// and the hackathon submission run (AUDITOR_PROVIDER unset or
// 'meta'). Selection is by server env ONLY (auditor.js auditorConfig)
// — never client-controllable.
//
// This module is a pure TRANSPORT with the same call shape as the
// Meta transport (callModel in auditor.js): it takes { system, user }
// and returns parsed JSON. Every rejection rule — unknown finding /
// evidence IDs, non-verbatim quotes, chain preconditions, refutation
// scope — stays in the existing validator layer (auditor.js,
// chains.js, refutation.js), which is provider-agnostic. The adapter
// creates no findings and validates nothing itself.
//
// Structured output choice: generationConfig sets
// responseMimeType 'application/json' and the prompts carry the
// output shapes, with parse + the existing validators behind it. A
// Gemini responseSchema was NOT mapped, deliberately: the contracts
// that matter are referential (IDs must exist in THIS report, quotes
// must be verbatim in THIS evidence) and no response schema can
// express them, so a schema would be a second, lossy source of truth
// next to the validators that actually enforce the contract.
//
// Endpoint/auth mirror the proven Oshudh implementation
// (~/workspace/oshudh/app/lib/providers/gemini.js):
// generativelanguage.googleapis.com, the key in the x-goog-api-key
// header (never in the URL, never in any returned value, log line,
// report, or stamp), GEMINI_API_KEY / GEMINI_MODEL env vars, and the
// lighter-model fallback on capacity errors (429/503/529).
export const GEMINI_DEFAULT_MODEL = 'gemini-3.8-flash';
export const GEMINI_FALLBACK_MODEL = 'gemini-3.5-flash-lite';
const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta';

export function geminiConfig(env = process.env) {
  const apiKey = env.GEMINI_API_KEY || '';
  return {
    provider: 'gemini',
    configured: Boolean(apiKey),
    modelId: env.GEMINI_MODEL || GEMINI_DEFAULT_MODEL,
    apiKeyPresent: Boolean(apiKey),
  };
}

function isCapacityError(err) {
  const msg = String((err && err.message) || '');
  return /\b(429|503|529)\b/.test(msg) || /overloaded|high demand/i.test(msg);
}

async function callGeminiOnce(model, apiKey, { system, user }, { timeoutMs, fetchFn }) {
  const res = await fetchFn(`${GEMINI_API_BASE}/models/${encodeURIComponent(model)}:generateContent`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-goog-api-key': apiKey,
    },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ parts: [{ text: user }] }],
      generationConfig: { responseMimeType: 'application/json', temperature: 0.2 },
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) {
    const errText = typeof res.text === 'function' ? await res.text().catch(() => '') : '';
    throw new Error(`Gemini API ${res.status}: ${String(errText).slice(0, 180)}`);
  }
  const body = await res.json();
  const text = ((body && body.candidates && body.candidates[0] && body.candidates[0].content && body.candidates[0].content.parts) || [])
    .map((p) => (p && typeof p.text === 'string' ? p.text : ''))
    .join('');
  if (!text) throw new Error('Gemini response has no message content');
  const clean = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
  try {
    return JSON.parse(clean);
  } catch {
    const m = clean.match(/\{[\s\S]*\}/);
    if (!m) throw new Error('Gemini response is not JSON');
    return JSON.parse(m[0]);
  }
}

// Same contract as the Meta transport: (config, { system, user },
// { timeoutMs }) -> parsed JSON, throwing on failure after the
// bounded attempt sequence. Attempts: the configured model, then
// the fallback model on capacity errors only (Oshudh pattern);
// config/parse errors throw immediately. On success the model that
// actually answered is recorded on the config object (usedModelId)
// so the pipeline can stamp the report honestly when the fallback
// engaged.
export async function callGemini(config, { system, user }, { timeoutMs = 20000, fetchFn = null } = {}) {
  const apiKey = process.env.GEMINI_API_KEY || '';
  if (!apiKey) throw new Error('GEMINI_API_KEY not set');
  const primary = config.modelId || GEMINI_DEFAULT_MODEL;
  const models = primary === GEMINI_FALLBACK_MODEL ? [primary] : [primary, GEMINI_FALLBACK_MODEL];
  const doFetch = fetchFn || globalThis.fetch;
  let lastErr = null;
  for (const model of models) {
    try {
      const out = await callGeminiOnce(model, apiKey, { system, user }, { timeoutMs, fetchFn: doFetch });
      config.usedModelId = model;
      return out;
    } catch (err) {
      if (!isCapacityError(err)) throw err;
      lastErr = err;
    }
  }
  throw lastErr || new Error('Gemini call failed');
}

// Coarse user-agent parsing (admin design §15.8): a deterministic,
// ordered parser with no dependency. It returns ONLY family labels —
// the raw UA string is discarded by callers after parsing and is
// never stored (not even as a hash: a UA hash adds linkability
// without serving any report this product makes).
//
// Phase 0/1 uses it for login/session audit families; the visitor
// beacon (Phase 2) reuses the same parser and classification.

const BOT_TOKENS = [
  'bot', 'crawler', 'spider', 'slurp', 'preview', 'monitor', 'headless',
  'facebookexternalhit', 'linkedinbot', 'slackbot', 'telegrambot',
  'discordbot', 'whatsapp', 'pingdom', 'uptimerobot', 'lighthouse',
  'pagespeed', 'gtmetrix', 'semrush', 'ahrefs', 'mj12', 'dotbot',
];

const COMMAND_LINE_TOKENS = [
  'curl/', 'wget/', 'python-requests', 'python-urllib', 'go-http-client',
  'axios/', 'okhttp', 'java/', 'libwww-perl', 'httpie', 'node-fetch',
  'undici', 'postmanruntime',
];

function includesAny(ua, tokens) {
  return tokens.some((t) => ua.includes(t));
}

export function parseUserAgent(rawUa) {
  const ua = typeof rawUa === 'string' ? rawUa : '';
  if (!ua.trim()) {
    return { browserFamily: 'Unknown', osFamily: 'Unknown', deviceFamily: 'Unknown', isBot: true };
  }
  const lower = ua.toLowerCase();
  if (includesAny(lower, BOT_TOKENS) || includesAny(lower, COMMAND_LINE_TOKENS)) {
    return { browserFamily: 'Bot', osFamily: 'Bot', deviceFamily: 'Bot', isBot: true };
  }

  // Browser: Edge and Opera before Chrome (their strings also carry
  // Chrome/Safari tokens); Samsung Internet before generic Chrome.
  let browserFamily = 'Other';
  if (lower.includes('edg/') || lower.includes('edga/') || lower.includes('edgios/')) browserFamily = 'Edge';
  else if (lower.includes('opr/') || lower.includes('opera')) browserFamily = 'Opera';
  else if (lower.includes('samsungbrowser/')) browserFamily = 'Samsung Internet';
  else if (lower.includes('crios/')) browserFamily = 'Chrome';
  else if (lower.includes('fxios/') || lower.includes('firefox/')) browserFamily = 'Firefox';
  else if (lower.includes('chromium/')) browserFamily = 'Chromium';
  else if (lower.includes('chrome/')) browserFamily = 'Chrome';
  else if (lower.includes('safari/')) browserFamily = 'Safari';

  // OS: iOS before macOS (iPhone strings say "like Mac OS X"),
  // Android before Linux, ChromeOS before generic Linux.
  let osFamily = 'Other';
  if (lower.includes('iphone') || lower.includes('ipad') || lower.includes('ipod') || lower.includes('cpu os') || lower.includes('cpu iphone os')) osFamily = 'iOS';
  else if (lower.includes('android')) osFamily = 'Android';
  else if (lower.includes('windows')) osFamily = 'Windows';
  else if (lower.includes('cros')) osFamily = 'ChromeOS';
  else if (lower.includes('mac os x') || lower.includes('macintosh')) osFamily = 'macOS';
  else if (lower.includes('linux')) osFamily = 'Linux';

  // Device.
  let deviceFamily = 'Desktop';
  if (lower.includes('ipad') || lower.includes('tablet')) deviceFamily = 'Tablet';
  else if (lower.includes('mobile') || lower.includes('iphone') || lower.includes('ipod')) deviceFamily = 'Mobile';
  else if (osFamily === 'Android') deviceFamily = 'Tablet';

  return { browserFamily, osFamily, deviceFamily, isBot: false };
}

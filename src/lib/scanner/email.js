// Group 7 — Email posture (SPF / DMARC) with the spec's DNS error
// taxonomy: NXDOMAIN, timeout and SERVFAIL are Inconclusive; only a
// confirmed empty answer (name exists, no TXT records) counts as
// "missing". DMARC policy is graded none -> reject.
import { makeCheck } from '../evidence.js';

const GROUP = 'email';

function dnsEvidence(ctx, host, result) {
  return ctx.evidence.add('dns', host, {
    query: `${host} TXT`,
    status: result.status,
    records: result.status === 'ok' ? result.records.slice(0, 10) : [],
  });
}

function inconclusiveDns(ctx, check, label, host, result) {
  const ev = dnsEvidence(ctx, host, result);
  return makeCheck({
    group: GROUP, check, outcome: 'inconclusive',
    title: `${label} could not be verified (DNS ${result.status})`,
    detail: `The DNS query for ${host} returned ${result.status}${result.code ? ` (${result.code})` : ''}. Per the error taxonomy this is inconclusive, not "missing": the record may exist and simply be unresolvable right now.`,
    evidenceIds: [ev],
  });
}

export async function runEmail(ctx) {
  const host = ctx.host();
  const out = [];

  // --- SPF at the target host ---
  const spf = await ctx.dnsTxt(host);
  if (spf.status !== 'ok' && spf.status !== 'empty') {
    out.push(inconclusiveDns(ctx, 'spf', 'SPF', host, spf));
  } else {
    const ev = dnsEvidence(ctx, host, spf);
    const records = spf.status === 'ok' ? spf.records.filter((r) => /^v=spf1(\s|$)/i.test(r)) : [];
    if (spf.status === 'empty' || records.length === 0) {
      out.push(
        makeCheck({
          group: GROUP, check: 'spf-missing', outcome: 'finding', severity: 'medium',
          title: 'SPF record missing',
          detail: spf.status === 'empty'
            ? 'A confirmed empty DNS answer: the host has no TXT records at all, so no SPF policy exists and any server can claim to send its mail.'
            : 'TXT records exist but none is an SPF policy (v=spf1), so receivers cannot tell legitimate senders from spoofers.',
          evidenceIds: [ev],
        })
      );
    } else if (records.length > 1) {
      out.push(
        makeCheck({
          group: GROUP, check: 'spf-multiple', outcome: 'finding', severity: 'low',
          title: 'Multiple SPF records published',
          detail: 'More than one v=spf1 record makes the policy invalid (RFC 7208 section 3.2); receivers treat it as no usable policy.',
          evidenceIds: [ev],
        })
      );
    } else {
      const record = records[0];
      const all = record.match(/([+~?-])all\b/i);
      if (!all) {
        out.push(
          makeCheck({
            group: GROUP, check: 'spf-no-all', outcome: 'finding', severity: 'low',
            title: 'SPF record has no "all" mechanism',
            detail: `The policy "${record}" never states what to do with unlisted senders, so its default is a neutral pass.`,
            evidenceIds: [ev],
          })
        );
      } else if (all[1] === '+') {
        out.push(
          makeCheck({
            group: GROUP, check: 'spf-plus-all', outcome: 'finding', severity: 'medium',
            title: 'SPF ends in +all (authorizes everyone)',
            detail: 'A +all mechanism tells receivers that literally any server may send this domain\'s mail, which defeats SPF entirely.',
            evidenceIds: [ev],
          })
        );
      } else if (all[1] === '?') {
        out.push(
          makeCheck({
            group: GROUP, check: 'spf-neutral', outcome: 'finding', severity: 'low',
            title: 'SPF ends in ?all (neutral)',
            detail: 'A neutral default gives receivers no signal about unlisted senders.',
            evidenceIds: [ev],
          })
        );
      } else {
        out.push(
          makeCheck({
            group: GROUP, check: 'spf', outcome: 'pass',
            title: `SPF present with a ${all[1] === '-' ? 'strict (-all)' : 'soft-fail (~all)'} default`,
            detail: `Policy: ${record}`,
            evidenceIds: [ev],
          })
        );
      }
    }
  }

  // --- DMARC at _dmarc.<host> ---
  const dmarcHost = `_dmarc.${host}`;
  const dmarc = await ctx.dnsTxt(dmarcHost);
  if (dmarc.status !== 'ok' && dmarc.status !== 'empty') {
    out.push(inconclusiveDns(ctx, 'dmarc', 'DMARC', dmarcHost, dmarc));
  } else {
    const ev = dnsEvidence(ctx, dmarcHost, dmarc);
    const records = dmarc.status === 'ok' ? dmarc.records.filter((r) => /^v=DMARC1(\s|;|$)/i.test(r)) : [];
    if (dmarc.status === 'empty' || records.length === 0) {
      out.push(
        makeCheck({
          group: GROUP, check: 'dmarc-missing', outcome: 'finding', severity: 'medium',
          title: 'DMARC record missing',
          detail: 'A confirmed empty answer at _dmarc: nothing tells receivers what to do with mail that fails SPF/DKIM alignment, so spoofed mail is delivered.',
          evidenceIds: [ev],
        })
      );
    } else {
      const record = records[0];
      const p = record.match(/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)/i);
      if (!p) {
        out.push(
          makeCheck({
            group: GROUP, check: 'dmarc-no-policy', outcome: 'finding', severity: 'low',
            title: 'DMARC record has no p= policy',
            detail: `The record "${record}" states no enforcement policy.`,
            evidenceIds: [ev],
          })
        );
      } else if (p[1].toLowerCase() === 'none') {
        out.push(
          makeCheck({
            group: GROUP, check: 'dmarc-p-none', outcome: 'finding', severity: 'low',
            title: 'DMARC policy is p=none (monitor only)',
            detail: 'p=none collects reports but instructs receivers to deliver failing mail anyway; spoofing stays possible.',
            evidenceIds: [ev],
          })
        );
      } else {
        out.push(
          makeCheck({
            group: GROUP, check: 'dmarc', outcome: 'pass',
            title: `DMARC enforced at p=${p[1].toLowerCase()}`,
            detail: `Record: ${record}`,
            evidenceIds: [ev],
          })
        );
      }
    }
  }

  return out;
}

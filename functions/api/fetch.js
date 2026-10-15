// Cloudflare Pages Function -> served at /api/fetch?url=https://...
// Fetches a public page and rewrites its asset URLs to go through this same endpoint,
// so the converter can read images, fonts and CSS without CORS problems.
// Optional: set env var ALLOWED_HOSTS="example.com,cdn.example.com" to restrict which sites can be loaded.

const MAX = 25 * 1024 * 1024;
const UA = 'Mozilla/5.0 (compatible; HTMLtoCreative/1.0)';

const bad = (msg, status = 400) => new Response(msg, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

function allowed(u, env) {
  if (!/^https?:$/.test(u.protocol)) return 'Only http and https links are allowed.';
  if (u.port && u.port !== '80' && u.port !== '443') return 'Custom ports are not allowed.';
  const h = u.hostname.toLowerCase();
  if (h === 'localhost' || /\.(local|localhost|internal|lan|home)$/.test(h) || !h.includes('.')) return 'That host is not allowed.';
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':') || h.startsWith('[')) return 'IP addresses are not allowed.';
  if (env && env.ALLOWED_HOSTS) {
    const list = env.ALLOWED_HOSTS.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    if (!list.some(a => h === a || h.endsWith('.' + a))) return 'That host is not on the allowed list.';
  }
  return '';
}

export async function onRequest({ request, env }) {
  const here = new URL(request.url), origin = here.origin;
  if (request.headers.get('Sec-Fetch-Site') === 'cross-site') return bad('Forbidden', 403);

  let target;
  try { target = new URL(here.searchParams.get('url')); } catch { return bad('Missing or invalid url parameter.'); }

  let res;
  for (let i = 0; i < 6; i++) {
    const why = allowed(target, env);
    if (why) return bad(why, 403);
    try {
      res = await fetch(target.href, { redirect: 'manual', headers: { 'User-Agent': UA, 'Accept': request.headers.get('Accept') || '*/*' } });
    } catch (e) { return bad('Could not reach that link.', 502); }
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) { target = new URL(loc, target); res = null; continue; }
    break;
  }
  if (!res) return bad('Too many redirects.', 508);
  if (!res.ok) return bad('The site answered with status ' + res.status + '.', 502);
  const len = +res.headers.get('content-length');
  if (len && len > MAX) return bad('That file is too large.', 413);

  const ct = res.headers.get('content-type') || '';
  const base0 = target.href;
  const hdr = (type) => ({ 'Content-Type': type, 'Cache-Control': 'public, max-age=600', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': 'sandbox' });
  const prox = (u, base) => {
    if (!u || /^\s*(data:|blob:|#|about:|javascript:|mailto:|tel:)/i.test(u)) return u;
    try { const a = new URL(u.trim(), base); return /^https?:$/.test(a.protocol) ? origin + '/api/fetch?url=' + encodeURIComponent(a.href) : u; } catch { return u; }
  };
  const css = (t, base) => t
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => 'url(' + q + prox(u, base) + q + ')')
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => '@import ' + q + prox(u, base) + q);

  if (/text\/css/i.test(ct)) return new Response(css(await res.text(), base0), { headers: hdr('text/css; charset=utf-8') });

  if (/text\/html|application\/xhtml/i.test(ct)) {
    let base = base0, buf = '';
    const attr = (name) => ({ element(el) { const v = el.getAttribute(name); if (v) el.setAttribute(name, prox(v, base)); } });
    const out = new HTMLRewriter()
      .on('base', { element(el) { const h = el.getAttribute('href'); if (h) { try { base = new URL(h, base0).href; } catch {} } el.remove(); } })
      .on('img,script,source,video,audio,embed,input,track', attr('src'))
      .on('img,video', attr('poster'))
      .on('link', attr('href'))
      .on('img,source', { element(el) {
        const v = el.getAttribute('srcset');
        if (v) el.setAttribute('srcset', v.split(',').map(p => { const [u, ...r] = p.trim().split(/\s+/); return [prox(u, base), ...r].join(' '); }).join(', '));
      } })
      .on('[style]', { element(el) { const v = el.getAttribute('style'); if (v) el.setAttribute('style', css(v, base)); } })
      .on('style', { text(t) { buf += t.text; t.remove(); if (t.lastInTextNode) { t.replace(css(buf, base), { html: true }); buf = ''; } } })
      .transform(new Response(res.body, { headers: { 'Content-Type': ct } }));
    return new Response(out.body, { headers: hdr('text/html; charset=utf-8') });
  }

  return new Response(res.body, { headers: hdr(ct || 'application/octet-stream') });
}

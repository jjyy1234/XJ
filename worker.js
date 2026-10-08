// ════════════════════════════════════════════════════════════════════════════
//  YUTONG PANEL v5.0 · Cloudflare Worker (Service Worker 格式，直接粘贴到控制台即可)
//  必需 KV 绑定(变量名必须一致): LOGS / PLAYERS / BLACKLIST / WHITELIST / META   —— 与旧版相同，无需新增
//  可选机密变量(Settings → Variables and Secrets):
//    SCRIPT_KEY         脚本通信密钥，须与 roblox.lua 里的 KEY 一致（强烈建议设置）
//    SECRET             会话签名密钥（不设会自动生成并存入 META）
//    SETUP_CODE         首次设置管理员时必须输入的“安装码”（防止别人抢先注册，强烈建议设置）
//    TURNSTILE_SITEKEY  Cloudflare Turnstile 站点密钥（可选，启用后真人验证叠加 Turnstile）
//    TURNSTILE_SECRET   Cloudflare Turnstile 私钥（与上面成对设置）
// ════════════════════════════════════════════════════════════════════════════
const G = n => (typeof globalThis[n] !== 'undefined' && globalThis[n]) ? String(globalThis[n]) : null;
const SECRET = G('SECRET'), SCRIPT_KEY = G('SCRIPT_KEY'), SETUP_CODE = G('SETUP_CODE'), TS_SITE = G('TURNSTILE_SITEKEY'), TS_SECRET = G('TURNSTILE_SECRET');
const V = '5.0.0', MAXH = 20, TTL = 7776000, ONT = 180, SESS_H = 12, HV_DIFF = 4;
const enc = new TextEncoder(), dec = new TextDecoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n || 8)));
const b64 = s => btoa(String.fromCharCode(...enc.encode(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ub64 = s => dec.decode(Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)));
const eq = (a, b) => { a = String(a); b = String(b); let r = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return !r };
const SEC = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-store',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload', 'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet',
  'Cross-Origin-Opener-Policy': 'same-origin', 'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()'
};
const J = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', ...SEC, ...h } });
const today = () => new Date().toISOString().slice(0, 10);
const BAD = /curl|wget|python|scrapy|httpclient|go-http|java\/|libwww|bot\b|spider|crawl|headless|phantom|selenium|puppeteer|playwright|axios|node-fetch|okhttp|aiohttp|httpx|postman|insomnia|masscan|nmap|zgrab|nikto|sqlmap|scanner|gptbot|ccbot|bytespider|semrush|ahrefs/i;
const HONEY = /^\/(wp-|wordpress|xmlrpc|\.env|\.git|\.aws|\.ssh|admin|administrator|phpmyadmin|pma|myadmin|config|backup|dump|vendor|cgi-bin|actuator|server-status|solr|boaform|HNAP1|setup\.php|login\.php|shell|console|manager|jenkins|api\/v1|graphql)/i;
const NOID = { error: 'noid', msg: '找不到该玩家，请填写 UserId 或准确的游戏名' };
const inc = (o, k) => { if (o[k] !== undefined || Object.keys(o).length < 30) o[k] = (o[k] || 0) + 1 };
const clean = (s, n) => String(s == null ? '' : s).replace(/[^\w .\-]/g, '').slice(0, n);
const getIp = r => r.headers.get('CF-Connecting-IP') || '0';
const getCc = r => (r.cf && r.cf.country) || '';
const getUa = r => r.headers.get('User-Agent') || '';
async function sha(s) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))) }

async function hmac(k, m) { const key = await crypto.subtle.importKey('raw', enc.encode(k), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); return hex(await crypto.subtle.sign('HMAC', key, enc.encode(m))) }
async function pbkdf2(pw, salt) { const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']); return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, k, 256)) }
let SECRET_CACHE = null;
async function secret() { if (SECRET) return SECRET; if (SECRET_CACHE) return SECRET_CACHE; let s = await META.get('config:secret'); if (!s) { s = rnd(32); await META.put('config:secret', s) } return SECRET_CACHE = s }
async function sign(o, ttl) { const p = b64(JSON.stringify({ ...o, x: Date.now() + ttl })); return p + '.' + await hmac(await secret(), p) }
async function verify(t) { if (typeof t !== 'string' || t.length > 2000) return null; const [p, s] = t.split('.'); if (!p || !s) return null; if (!eq(s, await hmac(await secret(), p))) return null; try { const o = JSON.parse(ub64(p)); return o.x > Date.now() ? o : null } catch { return null } }

// 内存限流（每个 isolate 内，零 KV 写入）；真正的洪水防护请配合 Cloudflare WAF 速率限制规则
const MEM = new Map();
function mrl(k, max, ms) { const n = Date.now(); let e = MEM.get(k); if (!e || e.t < n) { e = { t: n + ms, c: 0 }; MEM.set(k, e); if (MEM.size > 6000) for (const [kk, v] of MEM) if (v.t < n) MEM.delete(kk) } e.c++; return e.c <= max }
// KV 限流（跨 isolate 持久，只用于登录锁定等低频关键路径）
async function rl(k, max, ms) { const key = 'rl:' + k + ':' + Math.floor(Date.now() / ms); const n = +(await META.get(key) || 0); if (n >= max) return false; await META.put(key, String(n + 1), { expirationTtl: Math.max(60, Math.ceil(ms / 500)) }); return true }

let CC = null, CT = 0, CTX = null;
const DEF = { kill: false, killMsg: '服务维护中', wlRequired: false, announce: '', minVer: '', blockedPlaces: [], poll: 10, flags: {}, webhook: '', bc: null, susThreshold: 3, adminIps: [], autoBanSus: false };
async function getCfg(force) { if (!force && CC && Date.now() - CT < 8000) return CC; CC = { ...DEF, ...(await META.get('cfg', 'json') || {}) }; CT = Date.now(); return CC }
const baseStats = () => ({ logs: 0, players: 0, hwids: 0, susp: 0, days: {}, hrs: {}, places: {}, pn: {}, actions: {}, execs: {}, countries: {}, dau: {}, newp: {}, vers: {}, devs: {} });
async function stats() { return { ...baseStats(), ...(await META.get('stats', 'json') || {}) } }
async function bump(fn) {
  const s = await stats(); fn(s);
  let ks = Object.keys(s.days).sort(); while (ks.length > 30) delete s.days[ks.shift()];
  ks = Object.keys(s.hrs).sort(); while (ks.length > 48) delete s.hrs[ks.shift()];
  for (const f of ['dau', 'newp']) { const kk = Object.keys(s[f]).sort(); while (kk.length > 30) delete s[f][kk.shift()] }
  const top = Object.entries(s.places).sort((a, b) => b[1] - a[1]); if (top.length > 30) s.places = Object.fromEntries(top.slice(0, 30));
  for (const k of Object.keys(s.pn)) if (!(k in s.places)) delete s.pn[k];
  await META.put('stats', JSON.stringify(s));
}
async function hook(text) { try { const c = await getCfg(); if (!c.webhook) return; await fetch(c.webhook, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: String(text).slice(0, 1900) }) }) } catch { } }
const H = t => { const p = hook(t); if (CTX && CTX.waitUntil) CTX.waitUntil(p) };
async function audit(a) { const l = await META.get('audit', 'json') || []; l.unshift({ t: Date.now(), a }); await META.put('audit', JSON.stringify(l.slice(0, 120))) }
async function seclog(ev, req, x) { try { if (!mrl('sl:' + getIp(req) + ev, 6, 60000)) return; const l = await META.get('sec:log', 'json') || []; l.unshift({ t: Date.now(), e: ev, ip: getIp(req), cc: getCc(req), ua: getUa(req).slice(0, 90), x: x || '' }); await META.put('sec:log', JSON.stringify(l.slice(0, 100))) } catch { } }
const putOn = (id, o) => PLAYERS.put('on:' + id, '1', { expirationTtl: ONT, metadata: o });
async function pushCmd(id, c, m) { const k = 'cmd:' + id, a = await META.get(k, 'json') || []; a.push({ c, m: String(m || '').slice(0, 200) }); await META.put(k, JSON.stringify(a.slice(-10)), { expirationTtl: 3600 }) }
async function robloxName(id) { try { const x = await fetch('https://users.roblox.com/v1/users/' + id); const j = await x.json(); return j && j.name ? String(j.name).slice(0, 40) : null } catch { return null } }
const logPut = (p, a, pid, v, d, g, mt, now) => LOGS.put('log:' + String(9e15 - now).padStart(16, '0') + rnd(2), JSON.stringify({ u: p.user, i: p.userId, a, p: pid, t: now, h: (p.hw && p.hw[0]) || '', v, d, g, x: p.ex || '', ip: mt.ip, c: mt.cc }), { expirationTtl: TTL, metadata: { u: p.user, i: p.userId, a, p: pid, t: now, v } });
async function resolveId(v) {
  v = String(v || '').trim(); if (/^\d{1,12}$/.test(v)) return v;
  const n = v.toLowerCase().replace(/[^a-z0-9_]/g, ''); if (!n) return null;
  const r = await PLAYERS.list({ prefix: 'u:' + n + ':', limit: 1 }); if (r.keys.length) return r.keys[0].name.split(':').pop();
  try { const x = await fetch('https://users.roblox.com/v1/usernames/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ usernames: [v], excludeBannedUsers: false }) }); const j = await x.json(); if (j.data && j.data[0]) return String(j.data[0].id) } catch { }
  return null;
}

addEventListener('fetch', event => { event.respondWith(handleRequest(event.request, event)) });

async function handleRequest(req, event) {
  CTX = event;
  try {
    const u = new URL(req.url), p = u.pathname, m = req.method;
    if (p.startsWith('/s/')) return script(req, p, m);
    const ip = getIp(req);
    if (p === '/robots.txt') return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain', ...SEC } });
    if (p === '/favicon.ico' || p === '/favicon.svg') return new Response('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5ac8fa"/><stop offset="1" stop-color="#bf5af2"/></linearGradient></defs><rect width="64" height="64" rx="16" fill="url(#g)"/><path d="M20 20l12 14 12-14M32 34v12" stroke="#fff" stroke-width="6" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>', { headers: { 'Content-Type': 'image/svg+xml', ...SEC, 'Cache-Control': 'public, max-age=86400' } });
    if (!mrl('g:' + ip, 300, 60000)) return new Response('Too Many Requests', { status: 429, headers: { ...SEC, 'Retry-After': '60' } });
    // 蜜罐：扫描器常探测的路径 → 记录并临时封锁该 IP
    if (p !== '/' && !p.startsWith('/api/') && HONEY.test(p)) { await META.put('hp:' + ip, '1', { expirationTtl: 3600 }); await seclog('honeypot', req, p); return new Response('Not Found', { status: 404, headers: SEC }) }
    if (await META.get('hp:' + ip)) return new Response('Not Found', { status: 404, headers: SEC });
    if (p === '/' && (m === 'GET' || m === 'HEAD')) return page(req);
    if (p.startsWith('/api/')) return admin(req, u, p, m);
    return new Response('Not Found', { status: 404, headers: SEC });
  } catch (e) { return J({ error: 'server', msg: String(e && e.message || e).slice(0, 120) }, 500) }
}

// ============ 脚本端接口 (Roblox) ============
async function script(req, p, m) {
  if (m !== 'POST') return J({ ok: false }, 405);
  const ip = getIp(req), mt = { ip, cc: getCc(req) };
  if (SCRIPT_KEY && !eq(req.headers.get('X-K') || '', SCRIPT_KEY)) return J({ ok: false, msg: 'denied' }, 403);
  if (!mrl('s:' + ip, 240, 60000)) return J({ ok: false, msg: 'slow down' }, 429);
  let b, raw; try { raw = await req.text(); if (raw.length > 12000) return J({ ok: false }, 413); b = JSON.parse(raw) } catch { return J({ ok: false }, 400) }
  if (!b || typeof b !== 'object') return J({ ok: false }, 400);
  if (p === '/s/hello') return hello(b, mt);
  const t = await verify(b.t);
  if (!t || t.k !== 's') return J({ ok: false, msg: 'session' }, 401);
  if (!mrl('u:' + t.u, 150, 60000)) return J({ ok: false, msg: 'slow down' }, 429);
  if (p === '/s/event') return event(b, t, mt);
  if (p === '/s/poll') return poll(b, t);
  if (p === '/s/payload') { if (!t.w) return J({ ok: false, msg: 'wl' }, 403); const s = await META.get('payload'); return J({ ok: !!s, src: s || '' }) }
  return J({ ok: false }, 404);
}
async function hello(b, mt) {
  const id = String(b.userId || ''), name = String(b.user || '').slice(0, 40), hw = String(b.hwid || '').replace(/[^\w-]/g, '').slice(0, 80);
  if (!/^\d{1,12}$/.test(id) || !/^\w{1,40}$/.test(name)) return J({ ok: false, msg: 'bad request' }, 400);
  const ts = +b.ts || 0; if (Math.abs(Date.now() / 1000 - ts) > 300) return J({ ok: false, msg: '请更新脚本（时间校验失败，请确认设备时间正确）' });
  if (!mrl('h:' + id, 30, 60000) || !mrl('hi:' + mt.ip, 60, 60000)) return J({ ok: false, msg: 'slow down' }, 429);
  const cfg = await getCfg();
  if (cfg.kill) return J({ ok: false, msg: cfg.killMsg });
  const ban = await BLACKLIST.get('ban:' + id, 'json') || (hw && await BLACKLIST.get('hb:' + hw, 'json')) || (mt.ip && await BLACKLIST.get('ib:' + mt.ip, 'json'));
  if (ban) { H('🚫 被封禁的玩家尝试启动：' + name + ' (' + id + ')'); return J({ ok: false, banned: true, msg: ban.r || 'banned' }) }
  const wl = !!await WHITELIST.get('wl:' + id);
  if (cfg.wlRequired && !wl) return J({ ok: false, wl: false, msg: '未获得白名单' });
  if ((cfg.blockedPlaces || []).includes(String(b.placeId))) return J({ ok: false, msg: '此游戏暂不支持' });
  if (cfg.minVer && String(b.version || '') < cfg.minVer) return J({ ok: false, msg: '请更新脚本到 ' + cfg.minVer });
  const pid = String(b.placeId || '').replace(/\D/g, '').slice(0, 16);
  await touch(id, name, hw, { dn: clean(b.dn, 40), ag: Math.max(0, Math.min(+b.ag || 0, 99999)), ex: clean(b.ex, 30), dv: ['pc', 'mobile', 'console'].includes(b.dv) ? b.dv : '', ip: mt.ip, cc: mt.cc, ver: clean(b.version, 12), gn: String(b.gn || '').replace(/[\u0000-\u001f<>]/g, '').slice(0, 40) }, { a: 'execute', pid, g: clean(b.gameId, 40), mt }, cfg);
  const pf = await PLAYERS.get('pf:' + id, 'json') || {};
  await putOn(id, { i: id, u: name, p: pid, t: Date.now(), f: 0, pg: 0, c: mt.cc, g: clean(b.gameId, 8), dv: ['pc', 'mobile', 'console'].includes(b.dv) ? b.dv : '' });
  const token = await sign({ k: 's', u: id, w: wl, n: name, h: hw, c: mt.cc, d: ['pc', 'mobile', 'console'].includes(b.dv) ? b.dv : '' }, 30 * 60000);
  return J({ ok: true, token, wl, st: Date.now(), cfg: { announce: cfg.announce, flags: cfg.flags, pf, poll: cfg.poll, bc: cfg.bc ? cfg.bc.id : '' } });
}
async function touch(id, name, hw, x, ev, cfg) {
  const k = 'player:' + id, now = Date.now(), day = today(); let p = await PLAYERS.get(k, 'json');
  const fresh = !p, old = p && p.user, newDay = fresh || new Date(p.last || 0).toISOString().slice(0, 10) !== day, SUS = Math.max(1, +cfg.susThreshold || 3);
  if (fresh) p = { user: name, userId: id, hw: [], ips: [], n: 0, first: now, sus: false, ban: false, ev: [], note: '', tags: [] };
  p.user = name; p.last = now; p.dn = x.dn; p.ag = x.ag; p.ex = x.ex; p.dv = x.dv; p.cc = x.cc; p.ips = p.ips || []; p.hw = p.hw || []; p.ev = p.ev || [];
  if (x.ip && !p.ips.includes(x.ip)) { p.ips.unshift(x.ip); p.ips = p.ips.slice(0, 5) }
  if (ev) { p.n++; p.ev.unshift({ a: ev.a, t: now, p: ev.pid }); p.ev = p.ev.slice(0, 10) }
  let dh = 0, flag = [], ds = 0;
  if (hw && !p.hw.includes(hw)) {
    p.hw.unshift(hw); p.hw = p.hw.slice(0, MAXH);
    const hk = 'hwid:' + hw, d = await META.get(hk, 'json') || { u: [] };
    if (!d.u.includes(id)) {
      if (!d.u.length) dh = 1; d.u.push(id);
      await META.put(hk, JSON.stringify(d), { metadata: { n: d.u.length, t: now } });
      if (d.u.length > SUS) flag = d.u.slice(0, 8);
    }
  }
  if (flag.length && !p.sus) { p.sus = true; ds++ }
  await PLAYERS.put(k, JSON.stringify(p));
  if (ev) await logPut(p, ev.a, ev.pid, x.ver || '', '', ev.g || '', ev.mt, now);
  if (fresh || old !== name) await PLAYERS.put('u:' + name.toLowerCase() + ':' + id, '1');
  for (const o of flag) { if (o === id) continue; const q = await PLAYERS.get('player:' + o, 'json'); if (q && !q.sus) { q.sus = true; await PLAYERS.put('player:' + o, JSON.stringify(q)); ds++ } }
  if (fresh) H('🆕 新玩家：' + name + ' (' + id + ')' + (x.cc ? ' · ' + x.cc : '') + (x.ex ? ' · ' + x.ex : ''));
  if (ds) H('⚠️ 多账号设备已标记：' + name + ' (' + id + ')');
  if (ds && cfg.autoBanSus && hw) { const r = '多账号设备（自动）'; await BLACKLIST.put('hb:' + hw, JSON.stringify({ r, t: now, e: 0 }), { metadata: { h: hw, r, t: now, e: 0 } }); H('🔨 已自动封禁设备：' + hw.slice(0, 12)) }
  if (fresh || dh || ds || ev || newDay) await bump(s => {
    if (fresh) { s.players++; inc(s.execs, x.ex || 'unknown'); inc(s.countries, x.cc || '??'); inc(s.devs, x.dv || '?'); s.newp[day] = (s.newp[day] || 0) + 1 }
    if (newDay) s.dau[day] = (s.dau[day] || 0) + 1;
    s.hwids += dh; s.susp += ds;
    if (ev) { s.logs++; const hr = new Date().toISOString().slice(0, 13); s.days[day] = (s.days[day] || 0) + 1; s.hrs[hr] = (s.hrs[hr] || 0) + 1; if (ev.pid) { s.places[ev.pid] = (s.places[ev.pid] || 0) + 1; if (x.gn) s.pn[ev.pid] = x.gn } inc(s.actions, ev.a); if (x.ver) inc(s.vers, x.ver) }
  });
}
async function event(b, t, mt) {
  const a = String(b.action || 'execute').replace(/[^\w.-]/g, '').slice(0, 32) || 'execute', pid = String(b.placeId || '').replace(/\D/g, '').slice(0, 16), now = Date.now(), id = t.u, v = clean(b.version, 12);
  const k = 'player:' + id, p = await PLAYERS.get(k, 'json'); if (!p) return J({ ok: false, msg: 'session' }, 401);
  p.n++; p.last = now; p.ev = p.ev || []; p.ev.unshift({ a, t: now, p: pid }); p.ev = p.ev.slice(0, 10);
  await PLAYERS.put(k, JSON.stringify(p));
  const dataStr = b.data ? JSON.stringify(b.data).slice(0, 1200) : '';
  await logPut(p, a, pid, v, dataStr, clean(b.gameId, 40), mt, now);
  // 脚本错误单独写入 META 错误列表，便于「错误日志」页查看
  if (a === 'script_error' || a === 'error') {
    try {
      const el = await META.get('errlog', 'json') || [];
      const d = (b.data && typeof b.data === 'object') ? b.data : {};
      el.unshift({
        t: now, u: p.user, i: id, fn: String(d.fn || '').slice(0, 80),
        err: String(d.err || dataStr || '').slice(0, 800),
        extra: d.extra != null ? String(typeof d.extra === 'string' ? d.extra : JSON.stringify(d.extra)).slice(0, 300) : '',
        p: pid, v, x: p.ex || '', ip: mt.ip, c: mt.cc
      });
      await META.put('errlog', JSON.stringify(el.slice(0, 300)));
    } catch (e) { }
  }
  await bump(s => { s.logs++; const d = today(), hr = new Date().toISOString().slice(0, 13); s.days[d] = (s.days[d] || 0) + 1; s.hrs[hr] = (s.hrs[hr] || 0) + 1; if (pid) { s.places[pid] = (s.places[pid] || 0) + 1; if (b.gn) s.pn[pid] = String(b.gn).slice(0, 40) } inc(s.actions, a) });
  return J({ ok: true });
}
async function poll(b, t) {
  const id = t.u, c = [], cfg = await getCfg(), pid = String(b.placeId || '').replace(/\D/g, '').slice(0, 16);
  if (await BLACKLIST.get('ban:' + id) || (t.h && await BLACKLIST.get('hb:' + t.h))) c.push({ c: 'kick', m: '你已被封禁' });
  const q = await META.get('cmd:' + id, 'json'); if (q && q.length) { c.push(...q); await META.delete('cmd:' + id) }
  if (cfg.kill) c.push({ c: 'kick', m: cfg.killMsg });
  const bc = cfg.bc; if (bc && b.bc !== bc.id && (!bc.pl || bc.pl === pid)) c.push({ c: bc.c, m: bc.m });
  if ((+b.seq || 0) % 4 === 0) await putOn(id, { i: id, u: t.n, p: pid, t: Date.now(), f: Math.max(0, Math.round(+b.fps) || 0), pg: Math.max(0, Math.round(+b.ping) || 0), c: t.c || '', g: clean(b.gameId, 8), dv: t.d || '', m: Math.max(0, Math.round(+b.mem) || 0) });
  return J({ ok: true, cmds: c, cfg: { announce: cfg.announce, flags: cfg.flags, poll: cfg.poll, bc: bc ? bc.id : '' } });
}

// ============ 页面 ============
function csp(n) {
  const ts = TS_SITE ? ' https://challenges.cloudflare.com' : '';
  return "default-src 'none'; script-src 'nonce-" + n + "'" + ts + "; style-src 'nonce-" + n + "'; style-src-attr 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self' data:; connect-src 'self'; frame-src" + (TS_SITE ? ts : " 'none'") + "; worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";
}
async function page(req) {
  const ua = getUa(req);
  if (!ua || BAD.test(ua)) { await seclog('bot_page', req); return new Response('Forbidden', { status: 403, headers: SEC }) }
  const n = rnd(12), html = PAGE.split('__NONCE__').join(n).split('__TSKEY__').join(TS_SITE || '').split('__VER__').join(V);
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...SEC, 'Content-Security-Policy': csp(n) } });
}

// ============ 账号 / 会话 / 真人验证 ============
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = u8 => { let bits = '', o = ''; for (const b of u8) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) o += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return o };
const b32dec = s => { let bits = ''; for (const c of s.toUpperCase().replace(/=+$/, '')) { const i = B32.indexOf(c); if (i >= 0) bits += i.toString(2).padStart(5, '0') } const a = []; for (let i = 0; i + 8 <= bits.length; i += 8) a.push(parseInt(bits.slice(i, i + 8), 2)); return new Uint8Array(a) };
async function totp(sec, step) {
  const key = await crypto.subtle.importKey('raw', b32dec(sec), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']), buf = new ArrayBuffer(8), dv = new DataView(buf);
  dv.setUint32(0, Math.floor(step / 4294967296)); dv.setUint32(4, step >>> 0);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf)), o = h[19] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6).padStart(6, '0');
}
async function totpOk(sec, code) { code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code)) return false; const st = Math.floor(Date.now() / 30000); let ok = false; for (const d of [-1, 0, 1]) if (eq(await totp(sec, st + d), code)) ok = true; return ok }
const userOk = u => /^[A-Za-z0-9_]{3,24}$/.test(u);
function pwErr(pw, u) {
  if (pw.length < 8) return '密码至少需要 8 位'; if (pw.length > 128) return '密码太长了';
  if (/^\d+$/.test(pw)) return '密码不能是纯数字'; if (u && pw.toLowerCase() === String(u).toLowerCase()) return '密码不能与用户名相同';
  if (/^(password|qwertyui|abcdefgh|12345678|iloveyou|admin123|letmein1)/i.test(pw)) return '这个密码太常见了，换一个'; return '';
}
const ckSet = (name, v, age) => name + '=' + v + '; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=' + age;
const getCk = (req, n) => { const m = (req.headers.get('Cookie') || '').match(new RegExp('(?:^|; )' + n.replace(/[-_]/g, '\\$&') + '=([^;]+)')); return m && m[1] };
async function uah(req) { return (await sha(getUa(req))).slice(0, 16) }
async function humanOk(req) { const t = await verify(getCk(req, '__Host-yth')); return !!(t && t.k === 'h' && t.u === await uah(req)) }
async function hvIssue(req) {
  if (!mrl('hv:' + getIp(req), 25, 60000)) return J({ error: 'slow' }, 429);
  const r = rnd(8); return J({ c: await sign({ k: 'c', r, d: HV_DIFF, i: Date.now(), u: await uah(req) }, 120000), r, d: HV_DIFF, ts: TS_SITE ? 1 : 0 });
}
async function hvSolve(req, b) {
  const bad = (m) => J({ error: 'hv', msg: m || '验证失败，请重试' }, 400), t = await verify(b.c);
  if (!t || t.k !== 'c' || t.u !== await uah(req)) return bad('验证已过期，请重试');
  const age = Date.now() - t.i; if (age < 1500) return bad('操作太快了，请稍后再试'); if (age > 120000) return bad('验证已过期，请重试');
  const n = String(b.n == null ? '' : b.n).slice(0, 20), h = await sha(t.r + ':' + n); if (!h.startsWith('0'.repeat(t.d))) return bad();
  const hold = +b.hold || 0, ev = +b.ev || 0; if (hold < 900 || hold > 30000 || ev < 1) return bad('请按住按钮直到完成');
  if (await META.get('hvu:' + t.r)) return bad(); await META.put('hvu:' + t.r, '1', { expirationTtl: 300 });
  if (TS_SITE && TS_SECRET) {
    try {
      const fd = new FormData(); fd.append('secret', TS_SECRET); fd.append('response', String(b.ts || '')); fd.append('remoteip', getIp(req));
      const r = await (await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: fd })).json();
      if (!r.success) return bad('Turnstile 验证未通过');
    } catch { return bad('Turnstile 服务暂时不可用') }
  }
  return J({ ok: true }, 200, { 'Set-Cookie': ckSet('__Host-yth', await sign({ k: 'h', u: await uah(req) }, 1800000), 1800) });
}
async function mkSession(req) {
  const sid = rnd(12); await META.put('sess:' + sid, '1', { expirationTtl: SESS_H * 3600, metadata: { t: Date.now(), ip: getIp(req), cc: getCc(req), ua: getUa(req).slice(0, 80) } });
  return ckSet('__Host-yts', await sign({ k: 'a', s: sid, u: await uah(req) }, SESS_H * 3600000), SESS_H * 3600);
}
async function authed(req) {
  const t = await verify(getCk(req, '__Host-yts')); if (!t || t.k !== 'a' || t.u !== await uah(req)) return null;
  return await META.get('sess:' + t.s) ? t : null;
}
async function setup(req) {
  if (await META.get('adm')) return J({ error: 'done' }, 403);
  if (!await humanOk(req)) return J({ error: 'human' }, 403);
  if (!mrl('su:' + getIp(req), 10, 600000)) return J({ error: 'slow' }, 429);
  let b = {}; try { b = await req.json() } catch { }
  const u = String(b.u || '').trim(), pw = String(b.p || '');
  if (SETUP_CODE && !eq(String(b.code || ''), SETUP_CODE)) { await seclog('setup_badcode', req); return J({ error: 'code', msg: '安装码不正确' }, 403) }
  if (!userOk(u)) return J({ error: 'user', msg: '用户名需为 3–24 位字母、数字或下划线' }, 400);
  const e = pwErr(pw, u); if (e) return J({ error: 'pw', msg: e }, 400);
  const s = rnd(16); await META.put('adm', JSON.stringify({ u, s, h: await pbkdf2(pw, s), t: Date.now() }));
  await seclog('setup', req, u); await audit('创建管理员账号 ' + u);
  return J({ ok: true }, 200, { 'Set-Cookie': await mkSession(req) });
}
async function login(req) {
  const adm = await META.get('adm', 'json'), ip = getIp(req); if (!adm) return J({ error: 'nopw' }, 400);
  if (!await humanOk(req)) return J({ error: 'human' }, 403);
  const lk = 'lk:' + ip, n = +(await META.get(lk) || 0); if (n >= 5) { await seclog('login_locked', req); return J({ error: 'locked', msg: '尝试次数过多，请 15 分钟后再试' }, 429) }
  let b = {}; try { b = await req.json() } catch { }
  const h = await pbkdf2(String(b.p || ''), adm.s), okU = eq(String(b.u || '').toLowerCase(), adm.u.toLowerCase()), okP = eq(h, adm.h);
  let okO = true; if (adm.totp && adm.totp.on) okO = await totpOk(adm.totp.s, b.otp);
  if (!(okU && okP && okO)) { await META.put(lk, String(n + 1), { expirationTtl: 900 }); await seclog('login_fail', req, String(b.u || '').slice(0, 24)); await new Promise(r => setTimeout(r, 400)); return J({ error: 'invalid', left: Math.max(0, 4 - n) }, 401) }
  await META.delete(lk); await seclog('login_ok', req);
  return J({ ok: true }, 200, { 'Set-Cookie': await mkSession(req) });
}
async function killSessions(except) { let c; do { const r = await META.list({ prefix: 'sess:', limit: 500, cursor: c }); await Promise.all(r.keys.filter(k => k.name !== 'sess:' + except).map(k => META.delete(k.name))); c = r.list_complete ? null : r.cursor } while (c) }

const brief = p => ({ user: p.user, dn: p.dn, userId: p.userId, n: p.n, last: p.last, first: p.first, sus: p.sus, ban: p.ban, hwn: (p.hw || []).length, cc: p.cc, dv: p.dv, ex: p.ex, tags: p.tags || [] });
const lst = async (kv, prefix, cur, limit) => { const r = await kv.list({ prefix, limit, cursor: cur }); return { items: r.keys.map(k => ({ ...k.metadata, k: k.name })), cursor: r.list_complete ? null : r.cursor } };
const csvf = v => { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"' };
const hrs = h => Math.min(Math.max(+h || 0, 0), 24 * 3650);
const ttlOpt = h => h ? { expirationTtl: Math.max(60, Math.round(h * 3600)) } : {};
const validIp = ip => /^[0-9a-fA-F:.]{3,45}$/.test(ip);

async function banUser(id, r, h, device) {
  const t = Date.now(), e = h ? t + h * 3600000 : 0, x = await PLAYERS.get('player:' + id, 'json'), opt = ttlOpt(h);
  await BLACKLIST.put('ban:' + id, JSON.stringify({ r, t, e }), { metadata: { i: id, u: x ? x.user : ((await robloxName(id)) || ''), r, t, e }, ...opt });
  if (x) { x.ban = true; await PLAYERS.put('player:' + id, JSON.stringify(x)); if (device) for (const hw of (x.hw || []).slice(0, 3)) await BLACKLIST.put('hb:' + hw, JSON.stringify({ r, t, e }), { metadata: { h: hw, u: x.user, r, t, e }, ...opt }) }
  await pushCmd(id, 'kick', '你已被封禁：' + r); return x ? x.user : id;
}
async function wlAdd(id, h) {
  const x = await PLAYERS.get('player:' + id, 'json'), nm = x ? x.user : await robloxName(id); if (!nm) return null;
  const t = Date.now(), e = h ? t + h * 3600000 : 0;
  await WHITELIST.put('wl:' + id, JSON.stringify({ t, e }), { metadata: { i: id, u: nm, t, e }, ...ttlOpt(h) }); return nm;
}

// ============ 管理接口 ============
async function admin(req, u, p, m) {
  const ip = getIp(req), ua = getUa(req);
  if (!mrl('a:' + ip, 400, 60000)) return J({ error: 'rate' }, 429, { 'Retry-After': '60' });
  if (!ua || BAD.test(ua)) { await seclog('bot_api', req); return J({ error: 'denied' }, 403) }
  const sf = req.headers.get('Sec-Fetch-Site'); if (sf && sf !== 'same-origin' && sf !== 'none') return J({ error: 'denied' }, 403);
  const cfg = await getCfg(), allow = cfg.adminIps || [];
  if (allow.length && !allow.includes(ip)) { await seclog('ip_denied', req); return J({ error: 'nf' }, 404) }
  if (m === 'POST') {
    if (req.headers.get('X-YT') !== '1') return J({ error: 'csrf' }, 403);
    const o = req.headers.get('Origin'); if (o && o !== u.origin) return J({ error: 'origin' }, 403);
  }
  if (p === '/api/state') { const a = await META.get('adm', 'json'); return J({ setup: !a, authed: !!(a && await authed(req)), human: await humanOk(req), otp: !!(a && a.totp && a.totp.on), ts: TS_SITE || '', code: !!SETUP_CODE, v: V }) }
  if (p === '/api/hv' && m === 'GET') return hvIssue(req);
  if (p === '/api/hv' && m === 'POST') { let b = {}; try { b = await req.json() } catch { } return hvSolve(req, b) }
  if (p === '/api/setup' && m === 'POST') return setup(req);
  if (p === '/api/login' && m === 'POST') return login(req);
  const sess = await authed(req); if (!sess) return J({ error: 'unauthorized' }, 401);
  let b = {}; if (m === 'POST') { try { b = await req.json() } catch { } }
  const q = u.searchParams, cur = q.get('cursor') || undefined, who = async () => resolveId(b.userId); let mm;

  if (p === '/api/me') { const a = await META.get('adm', 'json'); return J({ ok: true, v: V, u: a.u, otp: !!(a.totp && a.totp.on), ip, cc: getCc(req), setup: !!SETUP_CODE, ts: !!TS_SITE, key: !!SCRIPT_KEY }) }
  if (p === '/api/diag') return J(Object.fromEntries(['LOGS', 'PLAYERS', 'BLACKLIST', 'WHITELIST', 'META'].map(n => [n, !!self[n]])));
  if (p === '/api/logout') { await META.delete('sess:' + sess.s); return J({ ok: true }, 200, { 'Set-Cookie': ckSet('__Host-yts', '', 0) }) }
  if (p === '/api/stats') {
    const [s, r, o] = await Promise.all([stats(), LOGS.list({ prefix: 'log:', limit: 40 }), PLAYERS.list({ prefix: 'on:', limit: 1000 })]);
    return J({ ...s, online: o.keys.length, recent: r.keys.filter(k => k.metadata && k.metadata.u && k.metadata.i).slice(0, 20).map(k => ({ ...k.metadata, k: k.name })) });
  }
  if (p === '/api/counts') { const f = async (kv, pr) => { let n = 0, c; do { const r = await kv.list({ prefix: pr, limit: 1000, cursor: c }); n += r.keys.length; c = r.list_complete ? null : r.cursor } while (c && n < 5000); return n }; const [a, d, i, w] = await Promise.all([f(BLACKLIST, 'ban:'), f(BLACKLIST, 'hb:'), f(BLACKLIST, 'ib:'), f(WHITELIST, 'wl:')]); return J({ ban: a, hb: d, ib: i, wl: w }) }
  if (p === '/api/online') {
    const [r, s] = await Promise.all([PLAYERS.list({ prefix: 'on:', limit: 1000 }), stats()]);
    return J({ list: r.keys.map(k => k.metadata).filter(x => x && x.i && x.u).sort((a, b) => b.t - a.t), pn: s.pn });
  }
  if (p === '/api/players') {
    const s = (q.get('q') || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
    if (/^\d+$/.test(s)) { const x = await PLAYERS.get('player:' + s, 'json'); return J({ players: x ? [brief(x)] : [], cursor: null }) }
    const r = await PLAYERS.list({ prefix: s ? 'u:' + s : 'player:', limit: 30, cursor: cur });
    const keys = r.keys.map(k => 'player:' + (s ? k.name.split(':').pop() : k.name.slice(7)));
    const ps = await Promise.all(keys.map(k => PLAYERS.get(k, 'json')));
    return J({ players: ps.filter(Boolean).map(brief), cursor: r.list_complete ? null : r.cursor });
  }
  if ((mm = p.match(/^\/api\/player\/(\d{1,12})$/))) {
    const id = mm[1], x = await PLAYERS.get('player:' + id, 'json'); if (!x) return J({ error: 'nf', msg: '没有找到该玩家' }, 404);
    const [wl, ban, on] = await Promise.all([WHITELIST.get('wl:' + id, 'json'), BLACKLIST.get('ban:' + id, 'json'), PLAYERS.list({ prefix: 'on:' + id, limit: 1 })]);
    const ids = new Set(); for (const h of (x.hw || []).slice(0, 3)) { const d = await META.get('hwid:' + h, 'json'); if (d) d.u.forEach(i => i !== id && ids.add(i)) }
    const alts = (await Promise.all([...ids].slice(0, 8).map(i => PLAYERS.get('player:' + i, 'json')))).filter(Boolean).map(brief);
    const om = on.keys.find(k => k.name === 'on:' + id);
    return J({ ...x, wl: !!wl, wlx: (wl && wl.e) || 0, banInfo: ban, online: !!om, om: om ? om.metadata : null, alts, pf: await PLAYERS.get('pf:' + id, 'json') || {} });
  }
  if (p === '/api/logs') { const r = await lst(LOGS, 'log:', cur, 100); return J({ logs: r.items.filter(x => x.u && x.i), cursor: r.cursor }) }
  if (p === '/api/log') { const k = q.get('k') || ''; if (!k.startsWith('log:')) return J({ error: 'bad key' }, 400); const d = await LOGS.get(k, 'json'); return d ? J(d) : J({ error: 'nf', msg: '日志已过期' }, 404) }
  if (p === '/api/export') {
    const rows = ['time,user,userId,action,placeId,version'];
    let c; for (let i = 0; i < 5; i++) { const r = await LOGS.list({ prefix: 'log:', limit: 1000, cursor: c }); for (const k of r.keys) { const x = k.metadata || {}; rows.push([new Date(x.t).toISOString(), x.u, x.i, x.a, x.p, x.v].map(csvf).join(',')) } if (r.list_complete) break; c = r.cursor }
    return new Response('\ufeff' + rows.join('\n'), { headers: { 'Content-Type': 'text/csv;charset=utf-8', 'Content-Disposition': 'attachment; filename=logs.csv', ...SEC } });
  }
  if (p === '/api/hwids') { const r = await lst(META, 'hwid:', cur, 100); return J({ list: r.items.map(x => ({ hwid: x.k.slice(5), n: x.n, t: x.t })).sort((a, b) => b.n - a.n), cursor: r.cursor }) }
  if ((mm = p.match(/^\/api\/hwid\/([\w-]{1,80})$/))) {
    const d = await META.get('hwid:' + mm[1], 'json'); if (!d) return J({ error: 'nf', msg: '没有找到该设备' }, 404);
    const [ps, ban] = await Promise.all([Promise.all(d.u.slice(0, 20).map(i => PLAYERS.get('player:' + i, 'json'))), BLACKLIST.get('hb:' + mm[1], 'json')]);
    return J({ accounts: ps.filter(Boolean).map(brief), banned: !!ban, ban });
  }
  if (p === '/api/bans') { const [a, d, ip2] = await Promise.all([lst(BLACKLIST, 'ban:', undefined, 500), lst(BLACKLIST, 'hb:', undefined, 500), lst(BLACKLIST, 'ib:', undefined, 500)]); return J({ list: a.items, dev: d.items, ips: ip2.items }) }
  if (p === '/api/wls') return J({ list: (await lst(WHITELIST, 'wl:', undefined, 1000)).items.filter(x => x.i && x.u) });
  if (p === '/api/audit') return J({ list: await META.get('audit', 'json') || [] });
  if (p === '/api/seclog') return J({ list: await META.get('sec:log', 'json') || [] });
  if (p === '/api/errlog') {
    if (m === 'GET') return J({ list: await META.get('errlog', 'json') || [] });
  }
  if (p === '/api/sessions') { const r = await META.list({ prefix: 'sess:', limit: 100 }); return J({ list: r.keys.map(k => ({ id: k.name.slice(5), cur: k.name === 'sess:' + sess.s, ...k.metadata })).sort((a, b) => b.t - a.t) }) }
  if (p === '/api/look' && m === 'GET') return J(await META.get('look', 'json') || {});
  if (p === '/api/cfg' && m === 'GET') return J(await getCfg(true));
  if (p === '/api/payload' && m === 'GET') return J({ src: await META.get('payload') || '' });
  if (p === '/api/backup') {
    const [w, a, d, i, c, pl, lk] = await Promise.all([lst(WHITELIST, 'wl:', undefined, 1000), lst(BLACKLIST, 'ban:', undefined, 1000), lst(BLACKLIST, 'hb:', undefined, 1000), lst(BLACKLIST, 'ib:', undefined, 1000), getCfg(true), META.get('payload'), META.get('look', 'json')]);
    return new Response(JSON.stringify({ app: 'yutong', v: V, t: Date.now(), cfg: c, payload: pl || '', wl: w.items, ban: a.items, hb: d.items, ib: i.items, look: lk || null }), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename=yutong-backup.json', ...SEC } });
  }
  if (m !== 'POST') return J({ error: 'not found' }, 404);

  if (p === '/api/ban') { const id = await who(); if (!id) return J(NOID, 400); const nm = await banUser(id, String(b.reason || 'banned').slice(0, 80), hrs(b.hours), b.device); await audit('封禁 ' + nm + (b.device ? '（含设备）' : '') + '：' + String(b.reason || '').slice(0, 40)); return J({ ok: true }) }
  if (p === '/api/unban') { const id = await who(); if (!id) return J(NOID, 400); await BLACKLIST.delete('ban:' + id); const x = await PLAYERS.get('player:' + id, 'json'); if (x) { x.ban = false; await PLAYERS.put('player:' + id, JSON.stringify(x)) } await audit('解封 ' + id); return J({ ok: true }) }
  if (p === '/api/hwban') {
    const hw = String(b.hwid || '').replace(/[^\w-]/g, '').slice(0, 80); if (!hw) return J({ error: 'bad', msg: 'HWID 无效' }, 400);
    const r = String(b.reason || 'banned').slice(0, 80), h = hrs(b.hours), t = Date.now(), e = h ? t + h * 3600000 : 0;
    await BLACKLIST.put('hb:' + hw, JSON.stringify({ r, t, e }), { metadata: { h: hw, r, t, e }, ...ttlOpt(h) }); await audit('封禁设备 ' + hw.slice(0, 12)); return J({ ok: true });
  }
  if (p === '/api/unhwban') { await BLACKLIST.delete('hb:' + String(b.hwid || '').replace(/[^\w-]/g, '')); await audit('解封设备'); return J({ ok: true }) }
  if (p === '/api/ipban') {
    const x = String(b.ip || '').trim(); if (!validIp(x)) return J({ error: 'bad', msg: 'IP 无效' }, 400);
    if (x === ip) return J({ error: 'self', msg: '不能封禁你当前的 IP' }, 400);
    const r = String(b.reason || 'banned').slice(0, 80), h = hrs(b.hours), t = Date.now(), e = h ? t + h * 3600000 : 0;
    await BLACKLIST.put('ib:' + x, JSON.stringify({ r, t, e }), { metadata: { ip: x, r, t, e }, ...ttlOpt(h) }); await audit('封禁 IP ' + x); return J({ ok: true });
  }
  if (p === '/api/unipban') { await BLACKLIST.delete('ib:' + String(b.ip || '').trim()); await audit('解封 IP'); return J({ ok: true }) }
  if (p === '/api/wl') { const id = await who(); if (!id) return J(NOID, 400); const nm = await wlAdd(id, hrs(b.hours)); if (!nm) return J({ error: 'noname', msg: '无法获取该玩家的名称，请稍后重试' }, 400); await audit('加入白名单 ' + nm); return J({ ok: true }) }
  if (p === '/api/unwl') { const id = await who(); if (!id) return J(NOID, 400); await WHITELIST.delete('wl:' + id); await audit('移出白名单 ' + id); return J({ ok: true }) }
  if (p === '/api/tags') { const id = await who(); const x = id && await PLAYERS.get('player:' + id, 'json'); if (!x) return J(NOID, 400); x.tags = (Array.isArray(b.tags) ? b.tags : []).map(v => String(v).trim().slice(0, 12)).filter(Boolean).slice(0, 5); await PLAYERS.put('player:' + id, JSON.stringify(x)); return J({ ok: true }) }
  if (p === '/api/note') { const id = await who(); const x = id && await PLAYERS.get('player:' + id, 'json'); if (!x) return J(NOID, 400); x.note = String(b.note || '').slice(0, 300); await PLAYERS.put('player:' + id, JSON.stringify(x)); return J({ ok: true }) }
  if (p === '/api/pflag') {
    const id = await who(); if (!id) return J(NOID, 400); const k = String(b.k || '').trim();
    if (!/^\w{1,32}$/.test(k)) return J({ error: 'bad', msg: '开关名只能用字母、数字、下划线' }, 400);
    const f = await PLAYERS.get('pf:' + id, 'json') || {}, sv = String(b.v == null ? '' : b.v);
    if (sv === '') delete f[k]; else { let v = sv; if (v === 'true') v = true; else if (v === 'false') v = false; else if (!isNaN(+v)) v = +v; f[k] = v }
    if (Object.keys(f).length) await PLAYERS.put('pf:' + id, JSON.stringify(f)); else await PLAYERS.delete('pf:' + id);
    if (sv !== '') await pushCmd(id, 'flag', k + '=' + sv); else await pushCmd(id, 'flag', k + '=');
    await audit('专属开关 ' + id + ' ' + k + (sv === '' ? ' 已删除' : '=' + sv)); return J({ ok: true });
  }
  if (p === '/api/cmd') {
    const id = await who(); if (!id) return J(NOID, 400);
    if (!['kick', 'notify', 'msg', 'teleport', 'rejoin', 'flag', 'ping', 'reload'].includes(b.c)) return J({ error: 'bad', msg: '不支持的指令' }, 400);
    if (b.c === 'flag' && !/^\w+=/.test(String(b.m || ''))) return J({ error: 'bad', msg: '格式：名称=值' }, 400);
    if (b.c === 'teleport' && !/^\d+$/.test(String(b.m || ''))) return J({ error: 'bad', msg: '请填写 PlaceId' }, 400);
    await pushCmd(id, b.c, b.m); await audit('指令 ' + b.c + ' → ' + id + (b.m ? '：' + String(b.m).slice(0, 40) : '')); return J({ ok: true });
  }
  if (p === '/api/bulk') {
    const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).map(x => String(x).replace(/\D/g, '')).filter(Boolean))].slice(0, 40); if (!ids.length) return J({ error: 'bad', msg: '没有选择玩家' }, 400);
    let n = 0;
    if (b.op === 'cmd') { if (!['kick', 'notify', 'msg', 'teleport', 'rejoin', 'reload'].includes(b.c)) return J({ error: 'bad', msg: '不支持的指令' }, 400); for (const id of ids) { await pushCmd(id, b.c, b.m); n++ } await audit('批量指令 ' + b.c + ' × ' + n) }
    else if (b.op === 'ban') { const r = String(b.reason || 'banned').slice(0, 80), h = hrs(b.hours); for (const id of ids) { await banUser(id, r, h, b.device); n++ } await audit('批量封禁 × ' + n + '：' + r.slice(0, 30)) }
    else if (b.op === 'unban') { for (const id of ids) { await BLACKLIST.delete('ban:' + id); n++ } await audit('批量解封 × ' + n) }
    else if (b.op === 'wl') { const h = hrs(b.hours); for (const id of ids) { if (await wlAdd(id, h)) n++ } await audit('批量加入白名单 × ' + n) }
    else if (b.op === 'unwl') { for (const id of ids) { await WHITELIST.delete('wl:' + id); n++ } await audit('批量移出白名单 × ' + n) }
    else return J({ error: 'bad' }, 400);
    return J({ ok: true, n });
  }
  if (p === '/api/bc') {
    if (!['notify', 'msg'].includes(b.c) || !String(b.m || '').trim()) return J({ error: 'bad', msg: '请输入内容' }, 400);
    const c = await getCfg(true); c.bc = { id: rnd(4), c: b.c, m: String(b.m).slice(0, 200), pl: String(b.pl || '').replace(/\D/g, ''), t: Date.now() };
    await META.put('cfg', JSON.stringify(c)); await getCfg(true); await audit('广播：' + c.bc.m.slice(0, 40)); return J({ ok: true });
  }
  if (p === '/api/cfg') {
    const old = await getCfg(true), w = String(b.webhook == null ? old.webhook : b.webhook).trim(), has = k => b[k] !== undefined;
    const c = {
      ...old,
      kill: has('kill') ? !!b.kill : old.kill, killMsg: has('killMsg') ? String(b.killMsg || '').slice(0, 100) : old.killMsg, wlRequired: has('wlRequired') ? !!b.wlRequired : old.wlRequired,
      announce: has('announce') ? String(b.announce || '').slice(0, 300) : old.announce, minVer: has('minVer') ? String(b.minVer || '').slice(0, 12) : old.minVer,
      blockedPlaces: has('blockedPlaces') ? (Array.isArray(b.blockedPlaces) ? b.blockedPlaces : []).map(x => String(x).replace(/\D/g, '')).filter(Boolean).slice(0, 200) : old.blockedPlaces,
      poll: has('poll') ? Math.min(Math.max(+b.poll || 10, 5), 120) : old.poll,
      flags: has('flags') ? ((b.flags && typeof b.flags === 'object' && !Array.isArray(b.flags) && JSON.stringify(b.flags).length < 3000) ? b.flags : {}) : old.flags,
      webhook: /^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//.test(w) ? w : '',
      susThreshold: has('susThreshold') ? Math.min(Math.max(+b.susThreshold || 3, 1), 20) : old.susThreshold, autoBanSus: has('autoBanSus') ? !!b.autoBanSus : old.autoBanSus
    };
    await META.put('cfg', JSON.stringify(c)); await getCfg(true); await audit('保存控制台配置'); return J({ ok: true });
  }
  if (p === '/api/payload') { const s = String(b.src || ''); if (s.length > 500000) return J({ error: 'too large' }, 400); if (s) await META.put('payload', s); else await META.delete('payload'); await audit('更新白名单专属代码'); return J({ ok: true }) }
  if (p === '/api/look') {
    const o = { t: Date.now() }; if (b.look && typeof b.look === 'object') { const s = JSON.stringify(b.look); if (s.length > 8000) return J({ error: 'big' }, 400); o.look = b.look }
    if (typeof b.bg === 'string') { if (b.bg.length > 1700000) return J({ error: 'big', msg: '背景图片太大' }, 400); o.bg = b.bg } else { const old = await META.get('look', 'json'); if (old && old.bg) o.bg = old.bg }
    await META.put('look', JSON.stringify(o)); return J({ ok: true, t: o.t });
  }
  if (p === '/api/secset') {
    const list = (Array.isArray(b.adminIps) ? b.adminIps : []).map(x => String(x).trim()).filter(Boolean).slice(0, 20);
    if (list.some(x => !validIp(x))) return J({ error: 'bad', msg: 'IP 格式不正确' }, 400);
    if (list.length && !list.includes(ip)) return J({ error: 'self', msg: '白名单必须包含你当前的 IP（' + ip + '），否则你会被锁在外面' }, 400);
    const c = await getCfg(true); c.adminIps = list; await META.put('cfg', JSON.stringify(c)); await getCfg(true); await audit('更新后台 IP 白名单（' + list.length + ' 个）'); return J({ ok: true });
  }
  if (p === '/api/pw') {
    const a = await META.get('adm', 'json'); if (!eq(await pbkdf2(String(b.old || ''), a.s), a.h)) { await seclog('pw_wrong', req); return J({ error: 'wrong', msg: '当前密码不正确' }, 400) }
    const nu = b.user ? String(b.user).trim() : a.u; if (!userOk(nu)) return J({ error: 'user', msg: '用户名需为 3–24 位字母、数字或下划线' }, 400);
    const np = String(b.new || ''); if (np) { const e = pwErr(np, nu); if (e) return J({ error: 'pw', msg: e }, 400) }
    const s = np ? rnd(16) : a.s; a.u = nu; a.s = s; if (np) a.h = await pbkdf2(np, s); await META.put('adm', JSON.stringify(a));
    await killSessions(); await seclog('pw_change', req); await audit('修改账号信息'); return J({ ok: true }, 200, { 'Set-Cookie': await mkSession(req) });
  }
  if (p === '/api/totp/new') { const a = await META.get('adm', 'json'); const s = b32enc(crypto.getRandomValues(new Uint8Array(20))); a.totp = { s, on: false }; await META.put('adm', JSON.stringify(a)); return J({ ok: true, secret: s, uri: 'otpauth://totp/Yutong:' + encodeURIComponent(a.u) + '?secret=' + s + '&issuer=Yutong&period=30&digits=6' }) }
  if (p === '/api/totp/on') { const a = await META.get('adm', 'json'); if (!a.totp || !await totpOk(a.totp.s, b.code)) return J({ error: 'bad', msg: '验证码不正确' }, 400); a.totp.on = true; await META.put('adm', JSON.stringify(a)); await audit('开启两步验证'); return J({ ok: true }) }
  if (p === '/api/totp/off') { const a = await META.get('adm', 'json'); if (!eq(await pbkdf2(String(b.p || ''), a.s), a.h)) return J({ error: 'wrong', msg: '密码不正确' }, 400); delete a.totp; await META.put('adm', JSON.stringify(a)); await audit('关闭两步验证'); return J({ ok: true }) }
  if (p === '/api/sess/revoke') { const id = String(b.id || '').replace(/[^\w]/g, ''); if (id === sess.s) return J({ error: 'self', msg: '这是当前会话，请用“退出登录”' }, 400); await META.delete('sess:' + id); await audit('撤销一个登录会话'); return J({ ok: true }) }
  if (p === '/api/sess/others') { await killSessions(sess.s); await audit('退出其他所有设备'); return J({ ok: true }) }
  if (p === '/api/restore') {
    const d = b.data || {}, cap = a => (Array.isArray(a) ? a : []).slice(0, 100); let n = 0;
    if (d.cfg && typeof d.cfg === 'object') { const old = await getCfg(true); await META.put('cfg', JSON.stringify({ ...DEF, ...d.cfg, adminIps: old.adminIps, bc: old.bc })); await getCfg(true); n++ }
    if (typeof d.payload === 'string' && d.payload.length < 500000) { if (d.payload) await META.put('payload', d.payload); n++ }
    const rest = async (arr, kv, pre, idf, valid) => { for (const x of cap(arr)) { const id = String(x[idf] || ''); if (!valid(id)) continue; const e = +x.e || 0; if (e && e < Date.now()) continue; const meta = { ...x }; delete meta.k; await kv.put(pre + id, JSON.stringify({ t: x.t || Date.now(), e, r: x.r || '' }), { metadata: meta, ...(e ? { expirationTtl: Math.max(60, Math.round((e - Date.now()) / 1000)) } : {}) }); n++ } };
    await rest(d.wl, WHITELIST, 'wl:', 'i', v => /^\d{1,12}$/.test(v)); await rest(d.ban, BLACKLIST, 'ban:', 'i', v => /^\d{1,12}$/.test(v));
    await rest(d.hb, BLACKLIST, 'hb:', 'h', v => /^[\w-]{1,80}$/.test(v)); await rest(d.ib, BLACKLIST, 'ib:', 'ip', validIp);
    await audit('导入备份（' + n + ' 项）'); return J({ ok: true, n });
  }
  if (p === '/api/cleanup') {
    const t = b.t === 'wl' ? 'wl' : 'logs', cu = b.cursor || undefined; let removed = 0;
    if (t === 'logs') {
      const r = await LOGS.list({ prefix: 'log:', limit: 100, cursor: cu }), bad = r.keys.filter(k => !(k.metadata && k.metadata.u && k.metadata.i));
      await Promise.all(bad.slice(0, 40).map(k => LOGS.delete(k.name))); removed = Math.min(bad.length, 40);
      return J({ ok: true, removed, again: bad.length > 40, cursor: r.list_complete ? null : r.cursor });
    }
    const r = await WHITELIST.list({ prefix: 'wl:', limit: 15, cursor: cu });
    for (const k of r.keys) {
      const m2 = k.metadata || {}; if (m2.i && m2.u) continue;
      const id = k.name.slice(3), nm = /^\d{1,12}$/.test(id) ? await robloxName(id) : null;
      if (nm) await WHITELIST.put(k.name, '{}', { metadata: { i: id, u: nm, t: m2.t || Date.now(), e: m2.e || 0 }, ...(m2.e ? { expirationTtl: Math.max(60, Math.round((m2.e - Date.now()) / 1000)) } : {}) });
      else { await WHITELIST.delete(k.name); removed++ }
    }
    return J({ ok: true, removed, cursor: r.list_complete ? null : r.cursor });
  }
  if (p === '/api/errlog/clear') { await META.delete('errlog'); await audit('清空脚本错误日志'); return J({ ok: true }) }
  if (p === '/api/clear') {
    const r = await LOGS.list({ prefix: 'log:', limit: 40 });
    await Promise.all(r.keys.map(k => LOGS.delete(k.name)));
    if (r.list_complete) { await bump(s => { s.logs = 0; s.days = {}; s.hrs = {}; s.places = {}; s.actions = {} }); await audit('清空日志') }
    return J({ ok: true, left: !r.list_complete });
  }
  return J({ error: 'not found' }, 404);
}


// ============ 前端页面（内嵌） ============
const PAGE = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover,maximum-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive,nosnippet,noimageindex"><meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#0b0d14"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>Yutong</title><link rel="icon" href="/favicon.svg">
<style nonce="__NONCE__">
:root{--accent:#0a84ff;--accent2:#bf5af2;--r:22px;--fs:15px;--font:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Helvetica Neue","Microsoft YaHei",sans-serif;--ls:0px;--t:1;--gap:16px;
--gb:28px;--gs:180%;--ga:.10;--gba:.16;--sh:.28;--spec:.22;--gl:255,255,255;--gbr:255,255,255;
--fg:#fff;--fg2:rgba(255,255,255,.68);--fg3:rgba(255,255,255,.42);--line:rgba(255,255,255,.10);--fill:rgba(255,255,255,.08);--fill2:rgba(255,255,255,.14);
--ok:#32d74b;--warn:#ff9f0a;--bad:#ff453a;--maxw:1240px;--sidew:236px;--bgblur:0px;--dim:.38;--bgsat:1.1;--bgbr:1;--px:0px;--py:0px;--ease:cubic-bezier(.32,.72,0,1);--spring:cubic-bezier(.34,1.46,.5,1)}
:root[data-mode=light]{--ga:.58;--gba:.7;--sh:.12;--spec:.9;--gl:255,255,255;--gbr:255,255,255;--fg:#12141c;--fg2:rgba(18,20,28,.68);--fg3:rgba(18,20,28,.42);--line:rgba(20,24,40,.10);--fill:rgba(20,24,40,.06);--fill2:rgba(20,24,40,.11)}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{color-scheme:dark;scroll-behavior:smooth}:root[data-mode=light]{color-scheme:light}
body{margin:0;min-height:100vh;font:400 var(--fs)/1.5 var(--font);letter-spacing:var(--ls);color:var(--fg);background:#0b0d14;-webkit-font-smoothing:antialiased;overflow-x:hidden}
body[data-tab=on] .num,body[data-tab=on] .tn{font-variant-numeric:tabular-nums}.tn,.num{font-variant-numeric:tabular-nums}
button,input,select,textarea{font:inherit;color:inherit;letter-spacing:inherit}
::selection{background:color-mix(in srgb,var(--accent) 45%,transparent)}
::-webkit-scrollbar{width:8px;height:8px}::-webkit-scrollbar-thumb{background:var(--fill2);border-radius:8px}::-webkit-scrollbar-track{background:transparent}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
[hidden]{display:none!important}
body.noanim *,body.noanim *::before,body.noanim *::after{animation-duration:.001s!important;transition-duration:.001s!important}
@media(prefers-reduced-motion:reduce){body:not(.forceanim) *,body:not(.forceanim) *::before{animation-duration:.001s!important;transition-duration:.001s!important}}
/* ── 背景层 ── */
#bg{position:fixed;inset:-6%;z-index:-4;background-size:cover;background-position:center;transform:translate3d(var(--px),var(--py),0) scale(1.06);filter:blur(var(--bgblur)) saturate(var(--bgsat)) brightness(var(--bgbr));transition:filter .5s,opacity .6s;will-change:transform}
#bg::after{content:"";position:absolute;inset:0;background:rgba(0,0,0,var(--dim));transition:background .4s}
:root[data-mode=light] #bg::after{background:rgba(255,255,255,calc(var(--dim)*.8))}
#aur{position:fixed;inset:0;z-index:-3;overflow:hidden;pointer-events:none;opacity:0;transition:opacity .8s}body.aur #aur{opacity:1}
#aur i{position:absolute;width:55vmax;height:55vmax;border-radius:50%;filter:blur(90px);opacity:.55;mix-blend-mode:screen;animation:float calc(var(--aurs,26s)) ease-in-out infinite alternate}
#aur i:nth-child(1){background:var(--accent);left:-15%;top:-20%}#aur i:nth-child(2){background:var(--accent2);right:-20%;top:5%;animation-delay:-7s}
#aur i:nth-child(3){background:#30d5c8;left:10%;bottom:-30%;animation-delay:-13s;opacity:.35}#aur i:nth-child(4){background:#ff375f;right:5%;bottom:-25%;animation-delay:-19s;opacity:.3}
@keyframes float{to{transform:translate3d(14vw,10vh,0) scale(1.25) rotate(40deg)}}
#cv{position:fixed;inset:0;z-index:-2;pointer-events:none;opacity:0;transition:opacity .6s}body.ptc #cv{opacity:1}
#grain{position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:0;mix-blend-mode:overlay;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='160' height='160' filter='url(%23n)' opacity='.55'/%3E%3C/svg%3E");transition:opacity .4s}body.grain #grain{opacity:.18}
/* ── 玻璃 ── */
.g{background:rgba(var(--gl),var(--ga));-webkit-backdrop-filter:blur(var(--gb)) saturate(var(--gs));backdrop-filter:blur(var(--gb)) saturate(var(--gs));border:1px solid rgba(var(--gbr),var(--gba));border-radius:var(--r);box-shadow:0 10px 40px rgba(0,0,0,var(--sh)),inset 0 1px 0 rgba(255,255,255,var(--spec));transition:background .3s,border-color .3s,box-shadow .3s}
body.noglass .g{-webkit-backdrop-filter:none;backdrop-filter:none;background:rgba(24,26,36,.88)}:root[data-mode=light] body.noglass .g{background:rgba(250,251,255,.92)}
.card{padding:calc(var(--gap)*1.15);margin-bottom:var(--gap);position:relative;overflow:hidden}
body.tilt .card.tl{transition:transform .25s var(--ease),box-shadow .3s}
.card h2{margin:0 0 calc(var(--gap)*.7);font-size:1.06em;font-weight:650;display:flex;align-items:center;gap:8px}
.card h2 .sp{flex:1}.sub{color:var(--fg2);font-size:.86em}.mut{color:var(--fg3)}.mono{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:.88em}
.lb{display:block;margin:calc(var(--gap)*.8) 2px 6px;font-size:.84em;color:var(--fg2);font-weight:550}
/* ── 布局 ── */
#app{display:flex;min-height:100vh}
#side{position:fixed;left:14px;top:14px;bottom:14px;width:var(--sidew);padding:18px 12px;display:flex;flex-direction:column;gap:4px;z-index:20;overflow:auto;animation:slideR calc(.7s*var(--t)) var(--ease) both}
.brand{display:flex;align-items:center;gap:11px;padding:4px 10px 16px;font-weight:700;font-size:1.12em}
.brand .lg{width:34px;height:34px;border-radius:11px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center;box-shadow:0 6px 18px color-mix(in srgb,var(--accent) 50%,transparent)}
.brand .lg svg{width:18px;height:18px}
.nv{display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:14px;color:var(--fg2);cursor:pointer;border:0;background:none;text-align:left;width:100%;position:relative;transition:background .2s,color .2s,transform .25s var(--spring)}
.nv svg{width:20px;height:20px;flex:none;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.nv:hover{background:var(--fill);color:var(--fg)}.nv:active{transform:scale(.96)}
.nv.on{color:var(--fg);background:var(--fill2);font-weight:600}.nv.on svg{stroke:var(--accent)}
.nv .bdg{margin-left:auto;font-size:.74em;padding:1px 8px;border-radius:99px;background:var(--accent);color:#fff;font-weight:600}
#side .sp{flex:1}
#main{flex:1;min-width:0;margin-left:calc(var(--sidew) + 28px);padding:18px 22px calc(40px + env(safe-area-inset-bottom));max-width:calc(var(--maxw) + var(--sidew) + 60px)}
#top{display:flex;align-items:center;gap:12px;margin:2px 0 calc(var(--gap)*1.1);padding-top:env(safe-area-inset-top)}
#top h1{margin:0;font-size:1.7em;font-weight:720;letter-spacing:-.02em;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#top .ib{width:40px;height:40px;border-radius:14px;display:grid;place-items:center;cursor:pointer;border:0;color:var(--fg);padding:0}
#top .ib svg{width:19px;height:19px;stroke:currentColor;fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
#top .ib:active{transform:scale(.92)}.ib{transition:transform .25s var(--spring)}
.live{display:inline-flex;align-items:center;gap:7px;font-size:.8em;color:var(--fg2);padding:0 4px}.live i{width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 0 var(--ok);animation:pulse 2s infinite}
@keyframes pulse{70%{box-shadow:0 0 0 9px transparent}100%{box-shadow:0 0 0 0 transparent}}
#view{max-width:var(--maxw)}
#dock{display:none;position:fixed;left:50%;bottom:calc(14px + env(safe-area-inset-bottom));transform:translateX(-50%);z-index:30;padding:7px;gap:2px;border-radius:30px;max-width:calc(100vw - 20px);overflow-x:auto;scrollbar-width:none}
#dock::-webkit-scrollbar{display:none}
#dock .nv{flex-direction:column;gap:3px;padding:9px 13px;font-size:.7em;width:auto;border-radius:22px;min-width:58px;align-items:center}
#dock .nv svg{width:22px;height:22px}#dock .nv .bdg{position:absolute;top:2px;right:6px;margin:0;padding:0 6px}
body[data-nav=dock] #side,body[data-nav=top] #side{display:none}body[data-nav=dock] #dock{display:flex}body[data-nav=dock] #main,body[data-nav=top] #main{margin-left:auto;margin-right:auto}
body[data-nav=dock] #main{padding-bottom:calc(110px + env(safe-area-inset-bottom))}
#tabs{display:none;gap:4px;overflow-x:auto;padding:6px;margin-bottom:var(--gap);scrollbar-width:none;border-radius:20px}#tabs::-webkit-scrollbar{display:none}
body[data-nav=top] #tabs{display:flex}#tabs .nv{width:auto;white-space:nowrap;padding:9px 15px}
@media(max-width:899px){body:not([data-nav=top]) #side{display:none}body:not([data-nav=top]) #dock{display:flex}body:not([data-nav=top]) #main{margin-left:auto;margin-right:auto;padding:14px 14px calc(110px + env(safe-area-inset-bottom))}#top h1{font-size:1.5em}}
@keyframes slideR{from{opacity:0;transform:translateX(-30px)}}@keyframes fadeUp{from{opacity:0;transform:translateY(16px)}}@keyframes zoomIn{from{opacity:0;transform:scale(.96)}}@keyframes fadeIn{from{opacity:0}}
body[data-pt=slide] .pgi>*{animation:fadeUp calc(.55s*var(--t)) var(--ease) both;animation-delay:calc(var(--i,0)*50ms*var(--t))}body[data-pt=fade] .pgi>*{animation:fadeIn calc(.4s*var(--t)) both;animation-delay:calc(var(--i,0)*40ms*var(--t))}body[data-pt=zoom] .pgi>*{animation:zoomIn calc(.5s*var(--t)) var(--ease) both;animation-delay:calc(var(--i,0)*50ms*var(--t))}
.ln{stroke-dasharray:1;animation:dr calc(1.3s*var(--t)) var(--ease) both}@keyframes dr{from{stroke-dashoffset:1}to{stroke-dashoffset:0}}.ar{animation:fadeIn calc(1.5s*var(--t)) both}.bar-r{transform-box:fill-box;transform-origin:bottom;animation:grow calc(.8s*var(--t)) var(--ease) both;animation-delay:calc(var(--i,0)*14ms*var(--t))}@keyframes grow{from{transform:scaleY(0)}}.seg-d{transition:stroke-dasharray calc(1.1s*var(--t)) var(--ease),stroke-width .25s,opacity .25s}
/* ── 网格 ── */
.grid{display:grid;gap:var(--gap);grid-template-columns:repeat(auto-fill,minmax(var(--gm,230px),1fr));margin-bottom:var(--gap)}.grid>.card{margin:0}
.g2{display:grid;gap:var(--gap);grid-template-columns:repeat(auto-fit,minmax(min(100%,420px),1fr));margin-bottom:var(--gap)}.g2>.card{margin:0}
.stat{cursor:pointer;transition:transform .35s var(--spring),box-shadow .3s}.stat:hover{transform:translateY(-3px)}.stat:active{transform:scale(.97)}
.stat .k{color:var(--fg2);font-size:.84em;display:flex;align-items:center;gap:7px}.stat .k i{width:8px;height:8px;border-radius:50%}
.stat .v{font-size:2.15em;font-weight:720;letter-spacing:-.03em;margin-top:2px;line-height:1.15}.stat .d{font-size:.8em;color:var(--fg3);margin-top:2px}
.stat svg.sk{position:absolute;right:0;bottom:0;width:58%;height:46%;opacity:.9;pointer-events:none}
/* ── 控件 ── */
.btn{border:0;border-radius:14px;padding:11px 18px;font-weight:600;cursor:pointer;color:#fff;background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent) 55%,var(--accent2)));box-shadow:0 6px 18px color-mix(in srgb,var(--accent) 38%,transparent),inset 0 1px 0 rgba(255,255,255,.3);transition:transform .25s var(--spring),filter .2s,opacity .2s;position:relative;overflow:hidden;white-space:nowrap}
.btn:hover{filter:brightness(1.08)}.btn:active{transform:scale(.95)}.btn:disabled{opacity:.4;pointer-events:none}
.btn.ghost{background:var(--fill);color:var(--fg);box-shadow:inset 0 0 0 1px var(--line)}.btn.ghost:hover{background:var(--fill2)}
.btn.red{background:linear-gradient(135deg,#ff453a,#ff2d55);box-shadow:0 6px 18px rgba(255,69,58,.35),inset 0 1px 0 rgba(255,255,255,.3)}
.btn.sm{padding:7px 13px;font-size:.86em;border-radius:11px}.btn.lg{padding:14px 22px;font-size:1.04em;border-radius:16px;width:100%}
.btn.busy::after{content:"";position:absolute;inset:0;margin:auto;width:18px;height:18px;border-radius:50%;border:2px solid #fff;border-top-color:transparent;animation:spin .7s linear infinite}.btn.busy{color:transparent}
@keyframes spin{to{transform:rotate(360deg)}}
.rip{position:absolute;border-radius:50%;background:rgba(255,255,255,.45);transform:scale(0);animation:rip .6s ease-out forwards;pointer-events:none}@keyframes rip{to{transform:scale(3);opacity:0}}
.bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:var(--gap)}.bar>.grow{flex:1;min-width:140px}
.in{width:100%;border:0;border-radius:14px;padding:12px 15px;background:var(--fill);box-shadow:inset 0 0 0 1px var(--line);outline:none;transition:box-shadow .2s,background .2s}
.in:focus{box-shadow:inset 0 0 0 2px var(--accent),0 0 0 5px color-mix(in srgb,var(--accent) 20%,transparent);background:var(--fill2)}.in::placeholder{color:var(--fg3)}
textarea.in{min-height:96px;resize:vertical;line-height:1.5}select.in{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23999' stroke-width='1.6' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:36px}
select.in option{color:#111;background:#fff}
.sw{position:relative;display:inline-block;width:52px;height:32px;flex:none}.sw input{position:absolute;opacity:0;inset:0;width:100%;height:100%;margin:0;cursor:pointer;z-index:2}
.sw s{position:absolute;inset:0;border-radius:99px;background:var(--fill2);transition:background .3s;box-shadow:inset 0 0 0 1px var(--line)}
.sw s::after{content:"";position:absolute;left:3px;top:3px;width:26px;height:26px;border-radius:50%;background:#fff;box-shadow:0 3px 8px rgba(0,0,0,.3);transition:transform calc(.4s*var(--t)) var(--spring),width .2s}
.sw input:checked+s{background:var(--ok)}.sw input:checked+s::after{transform:translateX(20px)}.sw input:active+s::after{width:32px}.sw input:checked:active+s::after{transform:translateX(14px)}
.sw.rd input:checked+s{background:var(--bad)}.sw input:disabled+s{opacity:.4}
.fl{display:flex;align-items:center;gap:14px;padding:12px 0;border-top:1px solid var(--line)}.fl:first-of-type{border-top:0}.fl>div:first-child{flex:1;min-width:0}.fl b{font-weight:600}
.dep{display:grid;grid-template-rows:1fr;transition:grid-template-rows calc(.45s*var(--t)) var(--ease),opacity .3s,filter .3s}.dep>div{overflow:hidden;min-height:0}.dep.off{grid-template-rows:0fr;opacity:0}.dep.dim{opacity:.38;filter:grayscale(1);pointer-events:none}
.seg{display:inline-flex;position:relative;background:var(--fill);border-radius:14px;padding:3px;box-shadow:inset 0 0 0 1px var(--line);max-width:100%;overflow-x:auto;scrollbar-width:none}.seg::-webkit-scrollbar{display:none}
.seg button{position:relative;z-index:1;border:0;background:none;padding:7px 14px;border-radius:11px;cursor:pointer;color:var(--fg2);font-weight:550;white-space:nowrap;transition:color .25s}.seg button.on{color:var(--fg)}
.seg .ind{position:absolute;top:3px;bottom:3px;border-radius:11px;background:var(--fill2);box-shadow:0 2px 8px rgba(0,0,0,.2),inset 0 1px 0 rgba(255,255,255,.15);transition:left calc(.4s*var(--t)) var(--spring),width calc(.4s*var(--t)) var(--spring)}
.rg{-webkit-appearance:none;appearance:none;width:100%;height:30px;background:transparent;outline:none;cursor:pointer;--p:50%}
.rg::-webkit-slider-runnable-track{height:6px;border-radius:6px;background:linear-gradient(90deg,var(--accent) var(--p),var(--fill2) var(--p))}.rg::-moz-range-track{height:6px;border-radius:6px;background:var(--fill2)}.rg::-moz-range-progress{height:6px;border-radius:6px;background:var(--accent)}
.rg::-webkit-slider-thumb{-webkit-appearance:none;width:26px;height:26px;border-radius:50%;background:#fff;margin-top:-10px;box-shadow:0 3px 10px rgba(0,0,0,.35);transition:transform .2s var(--spring)}.rg:active::-webkit-slider-thumb{transform:scale(1.18)}.rg::-moz-range-thumb{width:26px;height:26px;border:0;border-radius:50%;background:#fff}
.rgr{display:flex;align-items:center;gap:12px}.rgr output{min-width:48px;text-align:right;font-weight:600;font-variant-numeric:tabular-nums;color:var(--fg2)}
.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{border:0;border-radius:99px;padding:6px 14px;background:var(--fill);box-shadow:inset 0 0 0 1px var(--line);cursor:pointer;color:var(--fg2);font-weight:550;transition:all .25s var(--spring);font-size:.9em}.chip:hover{background:var(--fill2)}.chip:active{transform:scale(.93)}.chip.on{background:var(--accent);color:#fff;box-shadow:0 4px 14px color-mix(in srgb,var(--accent) 40%,transparent)}
.chip.x{display:inline-flex;align-items:center;gap:6px;cursor:default;padding-right:8px}.chip.x b{cursor:pointer;opacity:.6;font-weight:700;width:18px;height:18px;display:grid;place-items:center;border-radius:50%}.chip.x b:hover{opacity:1;background:var(--fill2)}
.tag{display:inline-block;padding:2px 9px;border-radius:99px;font-size:.74em;font-weight:650;background:var(--fill2);color:var(--fg2);margin-right:5px;white-space:nowrap}
.tag.ok{background:rgba(50,215,75,.18);color:var(--ok)}.tag.bad{background:rgba(255,69,58,.18);color:var(--bad)}.tag.warn{background:rgba(255,159,10,.18);color:var(--warn)}.tag.ac{background:color-mix(in srgb,var(--accent) 22%,transparent);color:var(--accent)}
.swatch{width:36px;height:36px;border-radius:50%;border:0;cursor:pointer;box-shadow:inset 0 0 0 2px rgba(255,255,255,.35);transition:transform .3s var(--spring)}.swatch:hover{transform:scale(1.12)}.swatch.on{box-shadow:0 0 0 3px var(--fg),inset 0 0 0 2px rgba(0,0,0,.3);transform:scale(1.1)}
input[type=color]{-webkit-appearance:none;border:0;padding:0;width:36px;height:36px;border-radius:50%;background:none;cursor:pointer}input[type=color]::-webkit-color-swatch-wrapper{padding:0}input[type=color]::-webkit-color-swatch{border:2px solid rgba(255,255,255,.4);border-radius:50%}
.bgs{display:grid;grid-template-columns:repeat(auto-fill,minmax(74px,1fr));gap:10px}.bgs div{aspect-ratio:1.4;border-radius:14px;cursor:pointer;background-size:cover;background-position:center;transition:transform .3s var(--spring),box-shadow .3s;position:relative;box-shadow:inset 0 0 0 1px rgba(255,255,255,.25)}.bgs div:hover{transform:scale(1.06)}.bgs div.on{box-shadow:0 0 0 3px var(--accent),0 8px 22px rgba(0,0,0,.4);transform:scale(1.05)}
.kv{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;margin-bottom:8px;animation:zoomIn .3s var(--ease)}.kv .in{padding:9px 12px}
.meter{height:6px;border-radius:6px;background:var(--fill2);overflow:hidden}.meter i{display:block;height:100%;width:0;border-radius:6px;background:var(--bad);transition:width .4s var(--ease),background .3s}
.chk{display:flex;gap:8px;align-items:center;font-size:.86em;color:var(--fg3);padding:2px 0;transition:color .3s}.chk i{width:16px;height:16px;border-radius:50%;background:var(--fill2);display:grid;place-items:center;font-style:normal;font-size:10px;color:transparent;transition:all .3s var(--spring)}.chk.ok{color:var(--ok)}.chk.ok i{background:var(--ok);color:#fff;transform:scale(1.15)}
/* ── 列表 ── */
.row{display:flex;align-items:center;gap:13px;padding:12px 6px;border-top:1px solid var(--line);cursor:pointer;border-radius:12px;transition:background .2s,transform .25s var(--spring);min-width:0}.row:first-child{border-top:0}.row:hover{background:var(--fill)}.row:active{transform:scale(.99)}
.row .grow{flex:1;min-width:0}.row .grow b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.row .grow span{display:block;color:var(--fg2);font-size:.84em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.row .end{text-align:right;font-size:.82em;color:var(--fg3);flex:none}
.row.sel{background:color-mix(in srgb,var(--accent) 18%,transparent)}
.av{width:42px;height:42px;border-radius:50%;display:grid;place-items:center;font-weight:700;color:#fff;flex:none;font-size:1.05em;text-shadow:0 1px 3px rgba(0,0,0,.3);box-shadow:inset 0 1px 0 rgba(255,255,255,.35),0 4px 12px rgba(0,0,0,.25)}.av.lgx{width:64px;height:64px;font-size:1.6em}
.pc{display:flex;flex-direction:column;gap:10px;cursor:pointer;transition:transform .35s var(--spring)}.pc:hover{transform:translateY(-3px)}.pc.sel{box-shadow:0 0 0 2px var(--accent),0 10px 40px rgba(0,0,0,var(--sh))}
.pc .tp{display:flex;gap:11px;align-items:center}.pc .m{display:flex;gap:7px;flex-wrap:wrap;font-size:.8em;color:var(--fg2)}.pc .m span{background:var(--fill);padding:2px 9px;border-radius:99px}
.dotx{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:5px}
.empty{text-align:center;padding:42px 16px;color:var(--fg3)}.empty svg{width:46px;height:46px;stroke:currentColor;fill:none;stroke-width:1.4;opacity:.6;margin-bottom:10px}
.sk-l{height:14px;border-radius:7px;background:linear-gradient(90deg,var(--fill) 25%,var(--fill2) 50%,var(--fill) 75%);background-size:200% 100%;animation:shim 1.3s infinite}@keyframes shim{to{background-position:-200% 0}}
.ldm{text-align:center;padding:16px;color:var(--fg3);font-size:.86em}
.kvs{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:12px 0}.kvs>div{background:var(--fill);border-radius:14px;padding:10px 13px;min-width:0}.kvs small{display:block;color:var(--fg3);font-size:.76em}.kvs b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:650}
.tl-i{display:flex;gap:12px;padding:8px 0;font-size:.9em;align-items:flex-start}.tl-i i{width:9px;height:9px;border-radius:50%;margin-top:7px;flex:none;background:var(--accent)}.tl-i .t{margin-left:auto;color:var(--fg3);font-size:.84em;white-space:nowrap}
/* ── 图表 ── */
.ch{width:100%;position:relative}.ch svg{width:100%;height:auto;display:block;overflow:visible}.ch .tip{position:absolute;pointer-events:none;background:rgba(20,22,32,.92);color:#fff;border-radius:12px;padding:8px 12px;font-size:.82em;opacity:0;transform:translate(-50%,-110%);transition:opacity .15s;white-space:nowrap;z-index:5;box-shadow:0 8px 24px rgba(0,0,0,.4)}
.ch text{fill:var(--fg3);font-size:11px}.ch .gl{stroke:var(--line)}.lgd{display:flex;gap:14px;flex-wrap:wrap;font-size:.82em;color:var(--fg2);margin-top:8px}.lgd span{display:inline-flex;align-items:center;gap:6px;cursor:pointer}.lgd i{width:10px;height:10px;border-radius:3px}
.hb{display:flex;align-items:center;gap:10px;margin:9px 0;font-size:.9em}.hb .n{width:30%;min-width:80px;max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.hb .b{flex:1;height:9px;border-radius:9px;background:var(--fill);overflow:hidden}.hb .b i{display:block;height:100%;border-radius:9px;background:linear-gradient(90deg,var(--accent),var(--accent2));width:0;transition:width calc(1s*var(--t)) var(--ease)}.hb .c{width:46px;text-align:right;color:var(--fg2);font-variant-numeric:tabular-nums}
/* ── 浮层 ── */
#ov{position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.42);-webkit-backdrop-filter:blur(6px);backdrop-filter:blur(6px);opacity:0;pointer-events:none;transition:opacity calc(.3s*var(--t))}#ov.on{opacity:1;pointer-events:auto}
#sheet{position:fixed;z-index:61;left:50%;top:50%;width:min(620px,calc(100vw - 24px));max-height:calc(100vh - 50px);overflow:auto;padding:22px;transform:translate(-50%,-46%) scale(.94);opacity:0;pointer-events:none;transition:transform calc(.45s*var(--t)) var(--spring),opacity calc(.25s*var(--t));overscroll-behavior:contain;background:rgba(var(--gl),calc(var(--ga) + .1))}
#sheet.on{transform:translate(-50%,-50%) scale(1);opacity:1;pointer-events:auto}#sheet.wide{width:min(860px,calc(100vw - 24px))}
@media(max-width:699px){#sheet{left:0;right:0;top:auto;bottom:0;width:100%;max-height:92vh;border-radius:28px 28px 0 0;transform:translateY(105%);padding:12px 16px calc(24px + env(safe-area-inset-bottom))}#sheet.on{transform:translateY(0)}#sheet::before{content:"";display:block;width:40px;height:5px;border-radius:5px;background:var(--fill2);margin:0 auto 14px}}
#sheet h2{margin:0 0 12px;font-size:1.3em}
#toasts{position:fixed;z-index:90;top:calc(14px + env(safe-area-inset-top));left:50%;transform:translateX(-50%);display:flex;flex-direction:column;gap:9px;align-items:center;pointer-events:none;width:calc(100vw - 24px)}body[data-toast=bottom] #toasts{top:auto;bottom:calc(100px + env(safe-area-inset-bottom))}
.toast{pointer-events:auto;padding:12px 18px;border-radius:99px;max-width:min(520px,100%);display:flex;gap:10px;align-items:center;font-weight:550;animation:tIn calc(.5s*var(--t)) var(--spring) both;background:rgba(var(--gl),calc(var(--ga) + .22))}.toast.out{animation:tOut .3s forwards}.toast i{width:9px;height:9px;border-radius:50%;background:var(--ok);flex:none}.toast.bad i{background:var(--bad)}.toast.warn i{background:var(--warn)}
@keyframes tIn{from{opacity:0;transform:translateY(-24px) scale(.85)}}@keyframes tOut{to{opacity:0;transform:translateY(-14px) scale(.9)}}
.bulk{position:fixed;left:50%;bottom:calc(112px + env(safe-area-inset-bottom));transform:translate(-50%,160%);z-index:35;padding:10px 14px;display:flex;gap:8px;align-items:center;border-radius:24px;max-width:calc(100vw - 20px);overflow-x:auto;transition:transform calc(.5s*var(--t)) var(--spring)}.bulk.on{transform:translate(-50%,0)}.bulk b{margin:0 6px;white-space:nowrap}
body[data-nav=side] .bulk{bottom:24px}@media(max-width:899px){body[data-nav=side] .bulk{bottom:calc(112px + env(safe-area-inset-bottom))}}
.savebar{position:sticky;bottom:calc(100px + env(safe-area-inset-bottom));z-index:30;padding:11px 14px;display:flex;gap:10px;align-items:center;justify-content:space-between;transform:translateY(200%);opacity:0;transition:transform calc(.5s*var(--t)) var(--spring),opacity .3s;margin-top:10px}.savebar.on{transform:none;opacity:1}
body[data-nav=side] .savebar{bottom:20px}
.banner{display:flex;align-items:center;gap:14px;padding:14px 18px;border-radius:var(--r);margin-bottom:var(--gap);background:linear-gradient(135deg,rgba(255,69,58,.28),rgba(255,45,85,.18));border:1px solid rgba(255,69,58,.45);animation:zoomIn .4s var(--ease)}.banner.warn{background:rgba(255,159,10,.2);border-color:rgba(255,159,10,.45)}.banner b{flex:1}
/* ── 登录页 ── */
#auth{position:fixed;inset:0;z-index:50;display:grid;place-items:center;padding:20px;overflow:auto}
.ac{width:min(420px,100%);padding:30px 26px;animation:zoomIn calc(.7s*var(--t)) var(--spring) both}.ac h1{margin:12px 0 4px;font-size:1.65em;text-align:center;letter-spacing:-.02em}.ac .lgo{width:60px;height:60px;border-radius:19px;margin:0 auto;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center;box-shadow:0 12px 34px color-mix(in srgb,var(--accent) 55%,transparent)}.ac .lgo svg{width:30px;height:30px}
.ac .sub{text-align:center;margin-bottom:18px}
.hv{display:flex;flex-direction:column;align-items:center;gap:14px;padding:6px 0 4px}
.ring{position:relative;width:128px;height:128px;border-radius:50%;cursor:pointer;touch-action:none;user-select:none;-webkit-user-select:none;transition:transform .3s var(--spring)}.ring:active,.ring.hold{transform:scale(.94)}
.ring .rb{position:absolute;inset:0;border-radius:50%;background:conic-gradient(var(--accent) calc(var(--pr,0)*1%),var(--fill2) 0);-webkit-mask:radial-gradient(circle,transparent 52px,#000 53px);mask:radial-gradient(circle,transparent 52px,#000 53px)}
.ring .rc{position:absolute;inset:14px;border-radius:50%;display:grid;place-items:center;background:rgba(var(--gl),calc(var(--ga) + .08));box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 6px 20px rgba(0,0,0,.25);font-weight:650;font-size:.92em;text-align:center;line-height:1.25;padding:6px}
.ring svg{width:46px;height:46px;stroke:var(--ok);fill:none;stroke-width:3.4;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:50;stroke-dashoffset:50}.ring.ok svg{animation:draw .6s .1s forwards}@keyframes draw{to{stroke-dashoffset:0}}
.ring.ok .rb{background:conic-gradient(var(--ok) 100%,transparent 0)}.ring.ok .rc{font-size:0}.ring.bad{animation:shake .45s}@keyframes shake{20%,60%{transform:translateX(-8px)}40%,80%{transform:translateX(8px)}}
.ring::before{content:"";position:absolute;inset:-6px;border-radius:50%;border:2px solid var(--accent);opacity:0;animation:rp 2.2s infinite}.ring.hold::before,.ring.ok::before,.ring.bad::before{animation:none}@keyframes rp{0%{transform:scale(.92);opacity:.5}100%{transform:scale(1.18);opacity:0}}
.lock{transition:filter .6s,opacity .6s,transform .6s var(--ease),max-height .6s;max-height:900px}.lock.off{filter:blur(8px);opacity:.35;pointer-events:none;transform:scale(.97)}
.err{color:var(--bad);font-size:.86em;min-height:1.3em;text-align:center;margin-top:10px}
.bm{position:fixed;inset:0;z-index:100;background:#000;display:grid;place-items:center;color:#fff;font-size:1.1em}
@media print{#side,#dock{display:none}}
</style></head>
<body><div id="bg"></div><div id="aur"><i></i><i></i><i></i><i></i></div><canvas id="cv"></canvas><div id="grain"></div>
<div id="auth" hidden></div>
<div id="app" hidden><aside id="side" class="g"></aside><main id="main"><header id="top"></header><nav id="tabs" class="g"></nav><div id="view"></div></main><nav id="dock" class="g"></nav></div>
<div id="bulk" class="bulk g"></div><div id="ov"></div><div id="sheet" class="g" role="dialog" aria-modal="true"></div><div id="toasts" aria-live="polite"></div>
<noscript><div class="bm">需要启用 JavaScript 才能使用控制台</div></noscript>
<script nonce="__NONCE__">
(()=>{'use strict';
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>(+n||0).toLocaleString('en-US');
const clamp=(v,a,b)=>Math.min(Math.max(v,a),b);
const ago=t=>{if(!t)return'—';const s=Math.max(0,(Date.now()-t)/1000);if(s<10)return'刚刚';if(s<60)return Math.floor(s)+' 秒前';if(s<3600)return Math.floor(s/60)+' 分钟前';if(s<86400)return Math.floor(s/3600)+' 小时前';if(s<2592000)return Math.floor(s/86400)+' 天前';return new Date(t).toLocaleDateString('zh-CN')};
const dt=t=>t?new Date(t).toLocaleString('zh-CN',{hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'}):'—';
const left=e=>{if(!e)return'永久';const s=(e-Date.now())/1000;if(s<=0)return'已过期';if(s<3600)return Math.ceil(s/60)+' 分钟';if(s<86400)return Math.floor(s/3600)+' 小时';return Math.floor(s/86400)+' 天'};
const flag=c=>c&&c.length===2?String.fromCodePoint(...[...c.toUpperCase()].map(x=>127397+x.charCodeAt())):'🌐';
const hue=s=>{let h=0;for(const c of String(s))h=(h*31+c.charCodeAt())%360;return h};
const av=(n,cls)=>{const h=hue(n);return \`<div class="av \${cls||''}" style="background:linear-gradient(135deg,hsl(\${h} 70% 58%),hsl(\${(h+40)%360} 75% 45%))">\${esc(String(n||'?').slice(0,1).toUpperCase())}</div>\`};
const IC={ov:'<rect x="3" y="3" width="7" height="9" rx="2"/><rect x="14" y="3" width="7" height="5" rx="2"/><rect x="14" y="12" width="7" height="9" rx="2"/><rect x="3" y="16" width="7" height="5" rx="2"/>',on:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',pl:'<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-7 7-7s7 3 7 7"/><path d="M16 4a4 4 0 010 8M22 21c0-3-2-5-4-6"/>',lg:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',bn:'<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',wl:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',hw:'<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',ct:'<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',sc:'<rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V8a4 4 0 018 0v3"/>',st:'<path d="M12 3a9 9 0 100 18c1.5 0 2-1 1.5-2-.6-1.2.2-2.5 1.6-2.5H17a4 4 0 004-4c0-5-4-9.5-9-9.5z"/><circle cx="7.5" cy="11" r="1"/><circle cx="10" cy="7" r="1"/><circle cx="15" cy="7.5" r="1"/>',search:'<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',refresh:'<path d="M20 11a8 8 0 10-2.3 6.3M20 4v7h-7"/>',out:'<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/>',empty:'<path d="M3 13l3-8h12l3 8v6H3z"/><path d="M3 13h5l1 3h6l1-3h5"/>',moon:'<path d="M20 14.5A8.5 8.5 0 119.5 4a7 7 0 0010.5 10.5z"/>',cmd:'<path d="M9 6a3 3 0 10-3 3h12a3 3 0 10-3-3v12a3 3 0 103-3H6a3 3 0 103 3z"/>',ok:'<path d="M5 12.5l4.5 4.5L19 7.5"/>'};
const ic=n=>\`<svg viewBox="0 0 24 24">\${IC[n]||''}</svg>\`;
const PAL=['#0a84ff','#bf5af2','#30d158','#ff9f0a','#ff375f','#64d2ff','#ffd60a','#ac8e68'];

/* ── 外观系统 ── */
const PRE=['linear-gradient(135deg,#1d2b64,#7b2ff7 55%,#f107a3)','radial-gradient(at 20% 15%,#4facfe,transparent 55%),radial-gradient(at 85% 20%,#c471f5,transparent 50%),radial-gradient(at 50% 95%,#fa71cd,transparent 55%),#0f1226','radial-gradient(at 15% 85%,#00c9a7,transparent 55%),radial-gradient(at 85% 15%,#0b6e99,transparent 55%),#06151f','linear-gradient(160deg,#2c0b3f,#a4357c 50%,#ff9966)','radial-gradient(at 80% 10%,#ff9a9e,transparent 50%),radial-gradient(at 10% 90%,#a18cd1,transparent 55%),#2a1a3a','linear-gradient(135deg,#0f2027,#203a43,#2c5364)','radial-gradient(at 30% 20%,#f6d365,transparent 50%),radial-gradient(at 80% 80%,#fda085,transparent 55%),#3b1f2b','linear-gradient(135deg,#232526,#414345)','radial-gradient(at 10% 10%,#00f5a0,transparent 45%),radial-gradient(at 90% 90%,#00d9f5,transparent 50%),#02121a','linear-gradient(135deg,#e0eafc,#cfdef3)'];
const LD={mode:'dark',acc:'#0a84ff',acc2:'#bf5af2',accAuto:1,bg:'p0',bgUrl:'',bgBlur:0,dim:38,bgSat:110,bgBr:100,par:0,aur:0,aurS:26,ptc:0,ptcN:60,grain:0,gb:28,ga:10,gs:180,gba:16,sh:28,spec:22,r:22,glass:1,font:'sys',fontCustom:'',fs:15,ls:0,nav:'side',gap:16,maxw:1240,anim:1,spd:100,pt:'slide',cnt:1,tilt:0,rip:1,hap:1,ref:10,toast:'top',cfm:1,dens:'cozy'};
const STYLES={ios:{n:'iOS 经典',v:{}},aurora:{n:'极光',v:{bg:'p1',aur:1,acc:'#64d2ff',acc2:'#bf5af2',dim:30,gb:34}},midnight:{n:'午夜',v:{bg:'p5',acc:'#5e5ce6',acc2:'#0a84ff',dim:50,ga:7,gba:12}},sakura:{n:'樱花',v:{bg:'p4',acc:'#ff6482',acc2:'#ff9f0a',dim:26,gb:36,r:28}},forest:{n:'森林',v:{bg:'p2',acc:'#30d158',acc2:'#64d2ff',dim:34}},mono:{n:'石墨',v:{bg:'p7',acc:'#e5e5ea',acc2:'#8e8e93',dim:45,r:16,gb:20}},neon:{n:'霓虹',v:{bg:'p8',acc:'#00f5a0',acc2:'#00d9f5',dim:55,aur:1,ptc:1,spec:35}},paper:{n:'纸白',v:{mode:'light',bg:'p9',acc:'#0a84ff',acc2:'#5e5ce6',dim:0,ga:58}}};
const FONTS={sys:['系统默认',''],round:['圆润','ui-rounded,"SF Pro Rounded","Hiragino Maru Gothic ProN","PingFang SC","Microsoft YaHei",sans-serif'],serif:['衬线','"New York","Songti SC","Noto Serif CJK SC",Georgia,serif'],song:['宋体','"Songti SC","SimSun","Noto Serif CJK SC",serif'],kai:['楷体','"Kaiti SC","KaiTi","STKaiti",serif'],mono:['等宽','ui-monospace,"SF Mono",Menlo,Consolas,monospace'],custom:['自定义','']};
let LK={...LD},lkT=0,lkSync=0,LKT=0;
try{Object.assign(LK,JSON.parse(localStorage.getItem('yt_look')||'{}'))}catch(e){}
const hsl2hex=(h,s,l)=>{s/=100;l/=100;const a=s*Math.min(l,1-l),f=n=>{const k=(n+h/30)%12,c=l-a*Math.max(Math.min(k-3,9-k,1),-1);return Math.round(255*c).toString(16).padStart(2,'0')};return '#'+f(0)+f(8)+f(4)};
const hex2hsl=x=>{let r=parseInt(x.slice(1,3),16)/255,g=parseInt(x.slice(3,5),16)/255,b=parseInt(x.slice(5,7),16)/255;const M=Math.max(r,g,b),m=Math.min(r,g,b);let h=0,s=0,l=(M+m)/2;if(M!==m){const d=M-m;s=l>.5?d/(2-M-m):d/(M+m);h=M===r?(g-b)/d+(g<b?6:0):M===g?(b-r)/d+2:(r-g)/d+4;h*=60}return[h,s*100,l*100]};
let BGDATA=localStorage.getItem('yt_bgimg')||'';
function bgCss(){if(LK.bg==='url'&&LK.bgUrl)return \`url("\${LK.bgUrl.replace(/"/g,'%22')}")\`;if(LK.bg==='data'&&BGDATA)return \`url("\${BGDATA}")\`;const i=+String(LK.bg).slice(1);return PRE[i]||PRE[0]}
function applyLook(sv){
 const r=document.documentElement.style,b=document.body,L=LK,set=(k,v)=>r.setProperty(k,v);
 const mode=L.mode==='auto'?(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'):L.mode;document.documentElement.dataset.mode=mode;
 set('--accent',L.acc);set('--accent2',L.acc2);set('--r',L.r+'px');set('--fs',L.fs+'px');set('--ls',L.ls+'px');set('--gap',({compact:12,cozy:16,roomy:22}[L.dens]||16)*L.gap/16+'px');set('--maxw',L.maxw+'px');
 set('--gb',(L.glass?L.gb:0)+'px');set('--gs',L.gs+'%');set('--ga',L.ga/100);set('--gba',L.gba/100);set('--sh',L.sh/100);set('--spec',L.spec/100);
 set('--bgblur',L.bgBlur+'px');set('--dim',L.dim/100);set('--bgsat',L.bgSat/100);set('--bgbr',L.bgBr/100);set('--aurs',L.aurS+'s');
 set('--t',L.anim?100/clamp(L.spd,25,300):0);
 const ff=L.font==='custom'?(L.fontCustom?\`"\${L.fontCustom.replace(/"/g,'')}",\`:'')+FONTS.sys[1]:FONTS[L.font]&&FONTS[L.font][1];if(ff)set('--font',ff);else r.removeProperty('--font');
 $('#bg').style.backgroundImage=bgCss();
 b.classList.toggle('noanim',!L.anim);b.classList.toggle('aur',!!L.aur&&!!L.anim);b.classList.toggle('ptc',!!L.ptc&&!!L.anim);b.classList.toggle('grain',!!L.grain);b.classList.toggle('noglass',!L.glass&&false);b.classList.toggle('tilt',!!L.tilt&&!!L.anim);
 b.dataset.nav=L.nav;b.dataset.pt=L.pt;b.dataset.toast=L.toast;
 $('meta[name=theme-color]').content=mode==='light'?'#eef1f8':'#0b0d14';
 ptcSet();parSet();
 try{localStorage.setItem('yt_look',JSON.stringify(L))}catch(e){}
 if(sv!==false&&authOk){clearTimeout(lkSync);lkSync=setTimeout(()=>api('look',{look:LK},{quiet:1}).catch(()=>{}),1600)}
}
function setLK(o,sv){Object.assign(LK,o);applyLook(sv)}
async function bgAccent(){try{const src=LK.bg==='url'?LK.bgUrl:LK.bg==='data'?BGDATA:'';if(!src)return toast('预设背景请直接选主题色，图片背景才能自动取色','warn');const im=new Image();im.crossOrigin='anonymous';await new Promise((ok,no)=>{im.onload=ok;im.onerror=no;im.src=src});const c=document.createElement('canvas');c.width=c.height=24;const x=c.getContext('2d');x.drawImage(im,0,0,24,24);const d=x.getImageData(0,0,24,24).data;let best=null,bs=-1;for(let i=0;i<d.length;i+=16){const[h,s,l]=hex2hsl('#'+[d[i],d[i+1],d[i+2]].map(v=>v.toString(16).padStart(2,'0')).join(''));const sc=s*(1-Math.abs(l-55)/55);if(sc>bs){bs=sc;best=h}}if(best==null)throw 0;setLK({acc:hsl2hex(best,78,58),acc2:hsl2hex((best+55)%360,72,62)});toast('已从背景提取主题色')}catch(e){toast('无法读取这张图片的颜色（图片站点禁止跨域读取，可改用“从相册选择”）','bad')}}
/* 粒子 / 视差 */
let pRaf=0,pts=[],mx=-999,my=-999;
function ptcSet(){const on=LK.ptc&&LK.anim;const c=$('#cv');if(!on){cancelAnimationFrame(pRaf);pRaf=0;return}c.width=innerWidth;c.height=innerHeight;const n=LK.ptcN;while(pts.length<n)pts.push({x:Math.random()*c.width,y:Math.random()*c.height,vx:(Math.random()-.5)*.35,vy:(Math.random()-.5)*.35,r:Math.random()*1.8+.6});pts.length=n;if(pRaf)return;const x=c.getContext('2d');const loop=()=>{if(document.hidden){pRaf=requestAnimationFrame(loop);return}x.clearRect(0,0,c.width,c.height);const col=LK.acc;for(const p of pts){p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>c.width)p.vx*=-1;if(p.y<0||p.y>c.height)p.vy*=-1;const dx=p.x-mx,dy=p.y-my,d=dx*dx+dy*dy;if(d<14000){p.x+=dx*.02;p.y+=dy*.02}x.fillStyle=col;x.globalAlpha=.7;x.beginPath();x.arc(p.x,p.y,p.r,0,6.3);x.fill()}x.strokeStyle=col;for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const a=pts[i],b=pts[j],d=Math.hypot(a.x-b.x,a.y-b.y);if(d<120){x.globalAlpha=(1-d/120)*.28;x.beginPath();x.moveTo(a.x,a.y);x.lineTo(b.x,b.y);x.stroke()}}pRaf=requestAnimationFrame(loop)};loop()}
function parSet(){const r=document.documentElement.style;if(!LK.par||!LK.anim){r.setProperty('--px','0px');r.setProperty('--py','0px')}}
addEventListener('pointermove',e=>{mx=e.clientX;my=e.clientY;if(LK.par&&LK.anim){const r=document.documentElement.style;r.setProperty('--px',((.5-e.clientX/innerWidth)*26)+'px');r.setProperty('--py',((.5-e.clientY/innerHeight)*26)+'px')}},{passive:true});
addEventListener('resize',()=>{if(pRaf)ptcSet()});
matchMedia('(prefers-color-scheme: light)').addEventListener('change',()=>{if(LK.mode==='auto')applyLook(false)});
/* 卡片 3D 倾斜 */
document.addEventListener('pointermove',e=>{if(!document.body.classList.contains('tilt')||e.pointerType==='touch')return;const c=e.target.closest&&e.target.closest('.stat,.pc');if(!c)return;const r=c.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;c.style.transform=\`perspective(700px) rotateX(\${-y*7}deg) rotateY(\${x*9}deg) translateY(-3px)\`},{passive:true});
document.addEventListener('pointerout',e=>{const c=e.target.closest&&e.target.closest('.stat,.pc');if(c&&!c.contains(e.relatedTarget))c.style.transform=''});

/* ── 基础 UI ── */
let authOk=false;
function hap(n){if(LK.hap&&navigator.vibrate)try{navigator.vibrate(n||8)}catch(e){}}
function toast(m,k){const t=document.createElement('div');t.className='toast g '+(k==='bad'||k===1?'bad':k==='warn'?'warn':'');t.innerHTML='<i></i><span>'+esc(m)+'</span>';$('#toasts').appendChild(t);setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),320)},k?4200:2600);if(k)hap(14)}
const err=e=>{if(e===0||e==null)return;toast((e&&e.msg)||(e&&e.error==='net'?'网络连接失败':'操作失败'),'bad')};
async function api(path,body,opt){opt=opt||{};const o={method:body===undefined?'GET':'POST',credentials:'same-origin',headers:{}};if(body!==undefined){o.headers['Content-Type']='application/json';o.headers['X-YT']='1';o.body=JSON.stringify(body)}let r;try{r=await fetch('/api/'+path,o)}catch(e){throw{error:'net',msg:'网络连接失败，请检查网络'}}let d=null;try{d=await r.json()}catch(e){}if(r.status===401&&d&&d.error==='unauthorized'){if(authOk&&!opt.quiet){authOk=false;showAuth()}throw 0}if(r.status===429)throw{error:'rate',msg:(d&&d.msg)||'请求太频繁，请稍后再试'};if(!r.ok||(d&&d.error))throw d||{error:'http',msg:'请求失败（'+r.status+'）'};return d}
function sheet(html,cb,wide){const s=$('#sheet');s.innerHTML=html;s.classList.toggle('wide',!!wide);s.scrollTop=0;$('#ov').classList.add('on');requestAnimationFrame(()=>{s.classList.add('on');post(s);cb&&cb(s)})}
let shutCb=null;function shut(){$('#sheet').classList.remove('on');$('#ov').classList.remove('on');const c=shutCb;shutCb=null;c&&c()}
$('#ov').addEventListener('click',shut);
function ask(o,back){return new Promise(res=>{let done=0;const fin=v=>{if(done)return;done=1;shutCb=null;if(v&&!back)shut();else if(back)back();else shut();res(v)};sheet(\`<h2>\${esc(o.t)}</h2><div class="sub" style="margin-bottom:14px;white-space:pre-wrap">\${esc(o.m||'')}</div>\${o.typed?\`<input class="in" id="ty" placeholder="输入 \${esc(o.typed)} 以确认" autocomplete="off">\`:''}<div class="bar" style="margin:18px 0 0"><button class="btn \${o.danger?'red':''}" id="ky" \${o.typed?'disabled':''}>\${esc(o.ok||'确定')}</button><button class="btn ghost" id="kn">取消</button></div>\`,s=>{if(o.typed)$('#ty').addEventListener('input',e=>{$('#ky').disabled=e.target.value!==o.typed});$('#ky').addEventListener('click',()=>fin(true));$('#kn').addEventListener('click',()=>fin(false));shutCb=()=>{if(!done){done=1;res(false)}}})})}
const needCfm=()=>LK.cfm;
async function danger(o,back){if(!needCfm())return true;return ask({danger:1,...o},back)}
function busy(b,p){b.classList.add('busy');b.disabled=true;return p.then(v=>{b.classList.remove('busy');b.disabled=false;return v},e=>{b.classList.remove('busy');b.disabled=false;throw e})}
const seg=(id,opts,val)=>\`<div class="seg" id="\${id}" data-v="\${esc(val)}"><i class="ind"></i>\${opts.map(o=>\`<button type="button" data-v="\${esc(o[0])}" class="\${String(o[0])===String(val)?'on':''}">\${esc(o[1])}</button>\`).join('')}</div>\`;
const segInd=s=>{const b=$('button.on',s),i=$('.ind',s);if(!b||!i)return;i.style.left=b.offsetLeft+'px';i.style.width=b.offsetWidth+'px'};
const rng=(id,mn,mx,st,v,u)=>\`<div class="rgr"><input type="range" class="rg" id="\${id}" min="\${mn}" max="\${mx}" step="\${st}" value="\${v}" data-u="\${u||''}"><output>\${v}\${u||''}</output></div>\`;
const rgFill=r=>{r.style.setProperty('--p',((r.value-r.min)/(r.max-r.min)*100)+'%');const o=r.nextElementSibling;if(o&&o.tagName==='OUTPUT')o.textContent=r.value+(r.dataset.u||'')};
const sw=(id,on,cls)=>\`<label class="sw \${cls||''}"><input type="checkbox" id="\${id}" \${on?'checked':''}><s></s></label>\`;
const flrow=(t,sub,ctl)=>\`<div class="fl"><div><b>\${t}</b>\${sub?\`<div class="sub">\${sub}</div>\`:''}</div>\${ctl}</div>\`;
function post(root){$$('.seg',root).forEach(segInd);$$('.rg',root).forEach(rgFill);requestAnimationFrame(()=>requestAnimationFrame(()=>$$('.hb .b i[data-w]',root).forEach(i=>i.style.width=i.dataset.w+'%')))}
document.addEventListener('click',e=>{const b=e.target.closest('.seg button');if(!b)return;const s=b.parentElement;if(s.dataset.v===b.dataset.v)return;s.dataset.v=b.dataset.v;$$('button',s).forEach(x=>x.classList.toggle('on',x===b));segInd(s);hap(6);s.dispatchEvent(new CustomEvent('chg',{bubbles:true,detail:b.dataset.v}))});
document.addEventListener('input',e=>{if(e.target.classList&&e.target.classList.contains('rg'))rgFill(e.target)});
document.addEventListener('change',e=>{if(e.target.closest&&e.target.closest('.sw'))hap(10)});
document.addEventListener('pointerdown',e=>{if(!LK.rip||!LK.anim)return;const b=e.target.closest('.btn');if(!b||b.disabled)return;const r=b.getBoundingClientRect(),d=Math.max(r.width,r.height),s=document.createElement('span');s.className='rip';s.style.cssText=\`width:\${d}px;height:\${d}px;left:\${e.clientX-r.left-d/2}px;top:\${e.clientY-r.top-d/2}px\`;b.appendChild(s);setTimeout(()=>s.remove(),620)});
document.addEventListener('click',e=>{const c=e.target.closest('.chip[data-pick]');if(!c)return;const g=c.parentElement;$$('.chip',g).forEach(x=>x.classList.toggle('on',x===c));g.dataset.v=c.dataset.pick;hap(6);g.dispatchEvent(new CustomEvent('chg',{bubbles:true,detail:c.dataset.pick}))});
function dep(el,show,mode){if(!el)return;el.classList.toggle(mode==='dim'?'dim':'off',!show);if(mode==='dim')return}
const depBox=(id,inner,show,mode)=>\`<div class="dep \${show?'':(mode==='dim'?'dim':'off')}" id="\${id}"><div>\${inner}</div></div>\`;
function cnt(el,to){to=+to||0;if(!LK.cnt||!LK.anim||el._v===to){el.textContent=fmt(to);el._v=to;return}const f=el._v||0,t0=performance.now(),D=700*(100/clamp(LK.spd,25,300));el._v=to;const st=n=>{const k=Math.min(1,(n-t0)/D),e=1-Math.pow(1-k,3);el.textContent=fmt(Math.round(f+(to-f)*e));if(k<1)requestAnimationFrame(st)};requestAnimationFrame(st)}
const skel=(n)=>Array.from({length:n||4},()=>'<div style="padding:14px 6px"><div class="sk-l" style="width:'+(50+Math.random()*40|0)+'%"></div><div class="sk-l" style="width:'+(25+Math.random()*30|0)+'%;margin-top:8px;height:10px"></div></div>').join('');
const emptyBox=(t,s)=>\`<div class="empty">\${ic('empty')}<div>\${esc(t||'这里还没有内容')}</div>\${s?\`<div class="sub">\${esc(s)}</div>\`:''}</div>\`;
const copy=t=>{(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>toast('已复制'),()=>{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();try{document.execCommand('copy');toast('已复制')}catch(e){toast('复制失败','bad')}a.remove()})};
const dl=(name,txt,type)=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt],{type:type||'application/json'}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),4000)};
const debounce=(f,ms)=>{let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>f(...a),ms)}};
const lines=s=>String(s||'').split(/[\\n,，\\s]+/).map(x=>x.trim()).filter(Boolean);
function infinite(box,load){let cur=null,end=false,busyF=false,io;const sent=document.createElement('div');sent.className='ldm';sent.textContent='加载中…';const more=async()=>{if(busyF||end)return;busyF=true;try{const r=await load(cur);cur=r.cursor;if(!cur){end=true;sent.textContent=r.empty?'':'没有更多了';io&&io.disconnect()}}catch(e){err(e);sent.textContent='加载失败，点击重试';sent.onclick=()=>{sent.onclick=null;sent.textContent='加载中…';busyF=false;more()}}busyF=false;if(!end&&sent.getBoundingClientRect().top<innerHeight+300&&sent.isConnected)setTimeout(more,60)};io=new IntersectionObserver(es=>{if(es[0].isIntersecting)more()},{rootMargin:'300px'});box.after(sent);io.observe(sent);more();return{stop(){io.disconnect();sent.remove()},reset(){cur=null;end=false;box.innerHTML='';sent.textContent='加载中…';io.observe(sent);more()}}}

/* ── 图表 ── */
let UID=0;
const smooth=pts=>{if(pts.length<2)return\`M\${pts[0][0]},\${pts[0][1]}\`;let d=\`M\${pts[0][0]},\${pts[0][1]}\`;for(let i=0;i<pts.length-1;i++){const p0=pts[i-1]||pts[i],p1=pts[i],p2=pts[i+1],p3=pts[i+2]||p2;d+=\`C\${p1[0]+(p2[0]-p0[0])/6},\${p1[1]+(p2[1]-p0[1])/6} \${p2[0]-(p3[0]-p1[0])/6},\${p2[1]-(p3[1]-p1[1])/6} \${p2[0]},\${p2[1]}\`}return d};
const nice=m=>{if(m<=4)return 4;const p=Math.pow(10,Math.floor(Math.log10(m))),n=m/p;return(n<=1.5?1.5:n<=2?2:n<=3?3:n<=5?5:10)*p};
const spark=(v,c)=>{if(!v||v.length<2)return'';const W=100,H=40,mx=Math.max(...v,1),pts=v.map((x,i)=>[i/(v.length-1)*W,H-4-(x/mx)*(H-10)]),id='s'+(++UID);return\`<svg class="sk" viewBox="0 0 \${W} \${H}" preserveAspectRatio="none"><defs><linearGradient id="\${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="\${c}" stop-opacity=".45"/><stop offset="1" stop-color="\${c}" stop-opacity="0"/></linearGradient></defs><path d="\${smooth(pts)}L\${W},\${H}L0,\${H}Z" fill="url(#\${id})" class="ar"/><path d="\${smooth(pts)}" fill="none" stroke="\${c}" stroke-width="1.8" vector-effect="non-scaling-stroke" stroke-linecap="round" class="ln" pathLength="1"/></svg>\`};
function areaChart(el,o){const W=640,H=o.h||210,L=34,R=10,T=12,B=24,hid=new Set(),n=o.labels.length;el.classList.add('ch');
 const draw=()=>{const vis=o.series.filter((_,i)=>!hid.has(i)),mx=nice(Math.max(1,...vis.flatMap(s=>s.vals))),X=i=>L+(n<2?0:i/(n-1))*(W-L-R),Y=v=>T+(1-v/mx)*(H-T-B);let g='';for(let k=0;k<=4;k++){const y=T+k/4*(H-T-B);g+=\`<line class="gl" x1="\${L}" x2="\${W-R}" y1="\${y}" y2="\${y}"/><text x="\${L-6}" y="\${y+4}" text-anchor="end">\${fmt(Math.round(mx*(1-k/4)))}</text>\`}
  const step=Math.ceil(n/7);for(let i=0;i<n;i+=step)g+=\`<text x="\${X(i)}" y="\${H-6}" text-anchor="middle">\${esc(o.labels[i])}</text>\`;
  const ss=o.series.map((s,si)=>{if(hid.has(si))return'';const pts=s.vals.map((v,i)=>[X(i),Y(v)]),id='a'+(++UID);return\`<defs><linearGradient id="\${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="\${s.color}" stop-opacity=".4"/><stop offset="1" stop-color="\${s.color}" stop-opacity="0"/></linearGradient></defs><path class="ar" d="\${smooth(pts)}L\${X(n-1)},\${H-B}L\${X(0)},\${H-B}Z" fill="url(#\${id})"/><path class="ln" pathLength="1" d="\${smooth(pts)}" fill="none" stroke="\${s.color}" stroke-width="2.6" stroke-linecap="round"/>\`}).join('');
  el.innerHTML=\`<svg viewBox="0 0 \${W} \${H}">\${g}\${ss}<line id="cl" y1="\${T}" y2="\${H-B}" stroke="var(--fg3)" stroke-dasharray="3 4" opacity="0"/><g id="cd"></g></svg><div class="tip"></div>\${o.series.length>1?\`<div class="lgd">\${o.series.map((s,i)=>\`<span data-i="\${i}" style="opacity:\${hid.has(i)?.4:1}"><i style="background:\${s.color}"></i>\${esc(s.name)}</span>\`).join('')}</div>\`:''}\`;
  const svg=$('svg',el),tip=$('.tip',el),cl=$('#cl',el),cd=$('#cd',el);
  const mv=e=>{const r=svg.getBoundingClientRect(),px=(e.clientX-r.left)/r.width*W,i=clamp(Math.round((px-L)/(W-L-R)*(n-1)),0,n-1),x=X(i);cl.setAttribute('x1',x);cl.setAttribute('x2',x);cl.style.opacity=1;cd.innerHTML=vis.map(s=>\`<circle cx="\${x}" cy="\${Y(s.vals[i])}" r="5" fill="\${s.color}" stroke="#fff" stroke-width="2"/>\`).join('');tip.innerHTML=\`<b>\${esc(o.labels[i])}</b>\`+vis.map(s=>\`<div><span style="color:\${s.color}">●</span> \${esc(s.name)} \${fmt(s.vals[i])}</div>\`).join('');tip.style.left=(x/W*r.width)+'px';tip.style.top=(Y(Math.max(...vis.map(s=>s.vals[i])))/H*r.height)+'px';tip.style.opacity=1};
  svg.addEventListener('pointermove',mv);svg.addEventListener('pointerleave',()=>{tip.style.opacity=0;cl.style.opacity=0;cd.innerHTML=''});
  $$('.lgd span',el).forEach(sp=>sp.addEventListener('click',()=>{const i=+sp.dataset.i;hid.has(i)?hid.delete(i):hid.add(i);if(hid.size>=o.series.length)hid.clear();draw()}))};draw()}
function barChart(el,o){const W=640,H=o.h||170,L=30,R=6,T=10,B=22,n=o.vals.length,mx=nice(Math.max(1,...o.vals)),bw=(W-L-R)/n;el.classList.add('ch');let g='';for(let k=0;k<=3;k++){const y=T+k/3*(H-T-B);g+=\`<line class="gl" x1="\${L}" x2="\${W-R}" y1="\${y}" y2="\${y}"/><text x="\${L-5}" y="\${y+4}" text-anchor="end">\${fmt(Math.round(mx*(1-k/3)))}</text>\`}
 const step=Math.ceil(n/8);for(let i=0;i<n;i+=step)g+=\`<text x="\${L+i*bw+bw/2}" y="\${H-5}" text-anchor="middle">\${esc(o.labels[i])}</text>\`;
 const id='b'+(++UID);const bars=o.vals.map((v,i)=>{const h=Math.max(v?3:0,v/mx*(H-T-B));return\`<rect class="bar-r" data-i="\${i}" style="--i:\${i}" x="\${L+i*bw+bw*.14}" y="\${H-B-h}" width="\${bw*.72}" height="\${h}" rx="\${Math.min(5,bw*.2)}" fill="url(#\${id})"/>\`}).join('');
 el.innerHTML=\`<svg viewBox="0 0 \${W} \${H}"><defs><linearGradient id="\${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="\${o.color||'var(--accent)'}"/><stop offset="1" stop-color="\${o.color2||'var(--accent2)'}"/></linearGradient></defs>\${g}\${bars}</svg><div class="tip"></div>\`;const tip=$('.tip',el),svg=$('svg',el);
 svg.addEventListener('pointermove',e=>{const r=svg.getBoundingClientRect(),i=clamp(Math.floor(((e.clientX-r.left)/r.width*W-L)/bw),0,n-1);tip.innerHTML=\`<b>\${esc(o.labels[i])}</b><div>\${fmt(o.vals[i])} 次</div>\`;tip.style.left=((L+i*bw+bw/2)/W*r.width)+'px';tip.style.top=((H-B-Math.max(3,o.vals[i]/mx*(H-T-B)))/H*r.height)+'px';tip.style.opacity=1});svg.addEventListener('pointerleave',()=>tip.style.opacity=0)}
function donut(el,data){const tot=data.reduce((a,b)=>a+b.v,0)||1,R=54,C=2*Math.PI*R;el.classList.add('ch');let off=0;const segs=data.map((d,i)=>{const len=d.v/tot*C,s=\`<circle class="seg-d" data-i="\${i}" cx="75" cy="75" r="\${R}" fill="none" stroke="\${d.c||PAL[i%8]}" stroke-width="20" stroke-dasharray="0 \${C}" data-len="\${Math.max(0,len-2)}" stroke-dashoffset="\${-off}" transform="rotate(-90 75 75)"/>\`;off+=len;return s}).join('');
 el.innerHTML=\`<div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap"><svg viewBox="0 0 150 150" style="width:150px;flex:none">\${segs}<text id="dn" x="75" y="73" text-anchor="middle" style="font-size:20px;font-weight:700;fill:var(--fg)">\${fmt(tot)}</text><text id="dl" x="75" y="92" text-anchor="middle" style="font-size:10px">总计</text></svg><div style="flex:1;min-width:130px">\${data.map((d,i)=>\`<div class="hb" data-i="\${i}" style="cursor:default;margin:6px 0"><i style="width:10px;height:10px;border-radius:3px;background:\${d.c||PAL[i%8]};flex:none"></i><span class="n" style="width:auto;flex:1;max-width:none">\${esc(d.n)}</span><span class="c" style="width:auto">\${fmt(d.v)} · \${Math.round(d.v/tot*100)}%</span></div>\`).join('')||'<span class="sub">暂无数据</span>'}</div></div>\`;
 requestAnimationFrame(()=>requestAnimationFrame(()=>$$('.seg-d',el).forEach(c=>c.setAttribute('stroke-dasharray',c.dataset.len+' '+C))));
 const hl=i=>{$$('.seg-d',el).forEach(c=>{c.style.opacity=i==null||+c.dataset.i===i?1:.3;c.setAttribute('stroke-width',+c.dataset.i===i?24:20)});if(i==null){$('#dn',el).textContent=fmt(tot);$('#dl',el).textContent='总计'}else{$('#dn',el).textContent=fmt(data[i].v);$('#dl',el).textContent=String(data[i].n).slice(0,10)}};
 $$('.seg-d,.hb[data-i]',el).forEach(x=>{x.addEventListener('pointerenter',()=>hl(+x.dataset.i));x.addEventListener('pointerleave',()=>hl(null))})}
const hbars=(rows,fmtN)=>{const mx=Math.max(1,...rows.map(r=>r[1]));return rows.length?rows.map(r=>\`<div class="hb"><span class="n" title="\${esc(r[0])}">\${fmtN?fmtN(r[0]):esc(r[0])}</span><span class="b"><i data-w="\${Math.max(3,r[1]/mx*100)}"></i></span><span class="c">\${fmt(r[1])}</span></div>\`).join(''):'<div class="sub">暂无数据</div>'};

/* ── 外壳与路由 ── */
const NAV=[['ov','概览'],['on','在线'],['pl','玩家'],['lg','日志'],['er','错误日志'],['bn','封禁'],['wl','白名单'],['hw','设备'],['ct','控制台'],['sc','安全'],['st','外观']];
const P={};let cur='',curEl=null,ME={},tickN=0;
function buildShell(){const items=NAV.map(n=>\`<button class="nv" data-p="\${n[0]}" aria-label="\${n[1]}">\${ic(n[0])}<span>\${n[1]}</span><b class="bdg" hidden></b></button>\`).join('');
 $('#side').innerHTML=\`<div class="brand"><div class="lg"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l6 7 6-7M12 13v6"/></svg></div>Yutong</div>\${items}<div class="sp"></div><button class="nv" id="lgo" style="margin-top:6px">\${ic('out')}<span>退出 · \${esc(ME.u||'')}</span></button>\`;
 $('#dock').innerHTML=items;$('#tabs').innerHTML=items;
 $('#top').innerHTML=\`<h1></h1><span class="live" id="lv" title="自动刷新"><i></i><span id="lvt"></span></span><button class="ib g" id="b-cmd" aria-label="搜索与命令">\${ic('search')}</button><button class="ib g" id="b-th" aria-label="切换明暗">\${ic('moon')}</button><button class="ib g" id="b-rf" aria-label="刷新">\${ic('refresh')}</button>\`;
 $$('.nv[data-p]').forEach(b=>b.addEventListener('click',()=>{hap(6);go(b.dataset.p)}));
 $('#lgo').addEventListener('click',logout);
 $('#b-cmd').addEventListener('click',palette);$('#b-th').addEventListener('click',()=>setLK({mode:(document.documentElement.dataset.mode==='light')?'dark':'light'}));
 $('#b-rf').addEventListener('click',()=>{const b=$('#b-rf svg');b.animate([{transform:'rotate(0)'},{transform:'rotate(360deg)'}],{duration:600,easing:'ease'});go(cur,1)});
 liveInd()}
function liveInd(){const l=$('#lv');if(!l)return;l.hidden=!LK.ref;$('#lvt').textContent=LK.ref?LK.ref+'s':''}
function go(id,force){if(!P[id])id='ov';if(cur===id&&!force)return;if(curEl&&curEl._x)curEl._x();cur=id;if(location.hash!=='#'+id)history.replaceState(null,'','#'+id);document.body.dataset.tab=id;$$('.nv[data-p]').forEach(n=>n.classList.toggle('on',n.dataset.p===id));const nb=$('#dock .nv.on');if(nb&&nb.scrollIntoView)nb.scrollIntoView({inline:'center',block:'nearest',behavior:'smooth'});$('#top h1').textContent=P[id].t;const v=$('#view');v.innerHTML='';const el=document.createElement('div');el.className='pgi';v.appendChild(el);curEl=el;try{P[id].r(el)}catch(e){console.error(e);el.innerHTML=emptyBox('页面加载失败',String(e&&e.message||e))}[...el.children].forEach((c,i)=>c.style.setProperty('--i',i));if(!force)scrollTo({top:0})}
function stagger(el){[...el.children].forEach((c,i)=>c.style.setProperty('--i',i))}
addEventListener('hashchange',()=>{const h=location.hash.slice(1);if(authOk&&P[h]&&h!==cur)go(h)});
setInterval(()=>{if(document.hidden||!authOk||!LK.ref||!curEl||!curEl._t||$('#sheet').classList.contains('on'))return;if(++tickN%LK.ref===0)curEl._t()},1000);
async function logout(){try{await api('logout',{},{quiet:1})}catch(e){}authOk=false;showAuth()}
/* ── 命令面板 ── */
function palette(){const acts=[...NAV.map(n=>({t:'前往 · '+n[1],k:n[0],f:()=>go(n[0])})),{t:'广播通知',k:'broadcast',f:()=>{go('ct');setTimeout(()=>{const b=$('#bcb');b&&b.click()},350)}},{t:'切换明暗主题',k:'theme dark light',f:()=>setLK({mode:document.documentElement.dataset.mode==='light'?'dark':'light'})},{t:'开关动态背景（极光）',k:'aurora',f:()=>setLK({aur:LK.aur?0:1})},{t:'退出登录',k:'logout',f:logout},...Object.entries(STYLES).map(([k,v])=>({t:'风格 · '+v.n,k:'style '+k,f:()=>applyStyle(k)}))];let sel=0,list=acts,pl=[];
 sheet(\`<input class="in" id="pq" placeholder="搜索玩家，或输入命令…" autocomplete="off"><div id="pr" style="margin-top:10px;max-height:52vh;overflow:auto"></div>\`,s=>{const q=$('#pq'),box=$('#pr');const draw=()=>{box.innerHTML=[...pl.map(p=>\`<div class="row" data-u="\${esc(p.userId)}">\${av(p.user)}<div class="grow"><b>\${esc(p.user)}</b><span>\${esc(p.userId)}</span></div></div>\`),...list.map((a,i)=>\`<div class="row \${i===sel?'sel':''}" data-a="\${acts.indexOf(a)}"><div class="grow"><b>\${esc(a.t)}</b></div></div>\`)].join('')||emptyBox('没有匹配项')};draw();q.focus();
  const sp=debounce(async v=>{try{const d=await api('players?q='+encodeURIComponent(v));pl=d.players.slice(0,5);draw()}catch(e){}},260);
  q.addEventListener('input',()=>{const v=q.value.trim().toLowerCase();list=acts.filter(a=>!v||(a.t+' '+a.k).toLowerCase().includes(v));sel=0;pl=[];draw();if(v.length>1)sp(v)});
  q.addEventListener('keydown',e=>{if(e.key==='ArrowDown'){sel=Math.min(list.length-1,sel+1);draw();e.preventDefault()}else if(e.key==='ArrowUp'){sel=Math.max(0,sel-1);draw();e.preventDefault()}else if(e.key==='Enter'){const a=list[sel];if(pl.length&&!a){pSheet(pl[0].userId)}else if(a){shut();a.f()}}});
  box.addEventListener('click',e=>{const r=e.target.closest('.row');if(!r)return;if(r.dataset.u)pSheet(r.dataset.u);else{shut();acts[+r.dataset.a].f()}})})}
document.addEventListener('keydown',e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'&&authOk){e.preventDefault();palette()}else if(e.key==='Escape')shut()});
/* ── 登录 / 首次设置 / 真人验证 ── */
const LOGO='<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l6 7 6-7M12 13v6"/></svg>';
async function solvePow(r,d){const E=new TextEncoder();let n=0;for(;;){const ps=[];for(let i=0;i<256;i++)ps.push(crypto.subtle.digest('SHA-256',E.encode(r+':'+(n+i))));const hs=await Promise.all(ps);for(let i=0;i<256;i++){const u=new Uint8Array(hs[i]);let ok=true;for(let k=0;k<d;k++){const nib=k%2?u[k>>1]&15:u[k>>1]>>4;if(nib){ok=false;break}}if(ok)return n+i}n+=256;await new Promise(r=>setTimeout(r,0))}}
function hvInit(box,st,onOk){box.innerHTML=\`<div class="hv"><div class="ring" id="rg" tabindex="0" role="button" aria-label="按住约 1.5 秒完成真人验证"><div class="rb"></div><div class="rc"><span id="rt">按住<br>验证</span><svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg></div></div><div class="sub" id="rs" style="margin:0">按住圆环约 1.5 秒，证明你不是机器人</div>\${st.ts?'<div id="tsw"></div>':''}</div>\`;
 const rg=$('#rg'),rs=$('#rs'),rt=$('#rt');let ch=null,pow=null,t0=0,tsTok=st.ts?'':'x',start=0,ev=0,raf=0,busyF=false,done=false;
 const prep=async()=>{try{ch=await api('hv',undefined,{quiet:1});t0=Date.now();pow=solvePow(ch.r,ch.d)}catch(e){rs.textContent=(e&&e.msg)||'无法连接服务器'}};prep();
 if(st.ts){const s=document.createElement('script');s.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';s.async=true;s.onload=()=>{try{turnstile.render('#tsw',{sitekey:st.ts,theme:'auto',callback:t=>{tsTok=t;rs.textContent='按住圆环约 1.5 秒完成验证'}})}catch(e){}};document.head.appendChild(s);rs.textContent='请先完成下方安全检查'}
 const fail=m=>{busyF=false;rg.classList.remove('hold');rg.classList.add('bad');rs.textContent=m;rs.style.color='var(--bad)';$('.rg') ;rg.style.setProperty('--pr',0);setTimeout(()=>{rg.classList.remove('bad');rs.style.color=''},600);prep();if(st.ts&&window.turnstile)try{turnstile.reset();tsTok=''}catch(e){}};
 const finish=async()=>{busyF=true;const held=Math.round(performance.now()-start);rg.classList.remove('hold');rt.innerHTML='验证中…';rs.textContent='正在校验…';try{if(!ch)throw{msg:'验证初始化失败，请重试'};const n=await pow;const wait=1800-(Date.now()-t0);if(wait>0)await new Promise(r=>setTimeout(r,wait));await api('hv',{c:ch.c,n,hold:held,ev,ts:tsTok},{quiet:1});done=true;rg.classList.add('ok');rs.textContent='验证通过';hap([12,40,12]);setTimeout(onOk,650)}catch(e){rt.innerHTML='按住<br>验证';fail((e&&e.msg)||'验证失败，请重试')}};
 const down=e=>{if(busyF||done||(e.isTrusted===false))return;if(!tsTok){toast('请先完成安全检查','warn');return}ev=1;start=performance.now();rg.classList.add('hold');rs.textContent='保持按住…';const tk=()=>{const p=Math.min(100,(performance.now()-start)/1500*100);rg.style.setProperty('--pr',p);if(p>=100&&rg.classList.contains('hold'))finish();else if(rg.classList.contains('hold'))raf=requestAnimationFrame(tk)};raf=requestAnimationFrame(tk)};
 const up=()=>{if(!rg.classList.contains('hold'))return;cancelAnimationFrame(raf);rg.classList.remove('hold');rg.style.setProperty('--pr',0);rs.textContent='再按久一点就好'};
 rg.addEventListener('pointerdown',e=>{rg.setPointerCapture&&rg.setPointerCapture(e.pointerId);down(e)});rg.addEventListener('pointerup',up);rg.addEventListener('pointercancel',up);rg.addEventListener('pointermove',e=>{if(rg.classList.contains('hold')&&e.isTrusted)ev++});
 rg.addEventListener('keydown',e=>{if((e.key===' '||e.key==='Enter')&&!e.repeat){e.preventDefault();down(e)}});rg.addEventListener('keyup',e=>{if(e.key===' '||e.key==='Enter')up()});rg.addEventListener('contextmenu',e=>e.preventDefault())}
const pwRules=(p,u)=>[['至少 8 位',p.length>=8],['不能是纯数字',p.length>0&&!/^\\d+$/.test(p)],['包含字母',/[A-Za-z]/.test(p)],['不与用户名相同',p.length>0&&p.toLowerCase()!==String(u).toLowerCase()]];
const pwScore=p=>(p.length>=8)+(p.length>=12)+(/[a-z]/.test(p)&&/[A-Z]/.test(p))+/\\d/.test(p)+/[^A-Za-z0-9]/.test(p);
async function showAuth(){authOk=false;$('#app').hidden=true;shut();const a=$('#auth');a.hidden=false;a.innerHTML='<div class="ac g"><div class="lgo">'+LOGO+'</div><h1>Yutong</h1><div class="sub">正在连接…</div></div>';let st;try{st=await api('state',undefined,{quiet:1})}catch(e){a.innerHTML=\`<div class="ac g"><div class="lgo">\${LOGO}</div><h1>连接失败</h1><div class="sub">\${esc((e&&e.msg)||'无法连接到服务器')}</div><button class="btn lg" id="rt">重试</button></div>\`;$('#rt').onclick=showAuth;return}
 if(st.authed){enter();return}authUI(st)}
function authUI(st){const a=$('#auth'),setup=st.setup;
 a.innerHTML=\`<div class="ac g"><div class="lgo">\${LOGO}</div><h1>\${setup?'创建管理员账号':'登录控制台'}</h1><div class="sub">\${setup?'首次使用 · 先完成真人验证，再设置你自己的账号':'完成真人验证后即可登录'}</div><div id="hvb"></div><div class="lock \${st.human?'':'off'}" id="lk"><form id="af" autocomplete="on" novalidate>
 \${setup&&st.code?'<label class="lb">安装码（Worker 变量 SETUP_CODE）</label><input class="in" id="ac" type="password" autocomplete="off" spellcheck="false">':''}
 <label class="lb">用户名</label><input class="in" id="au" autocomplete="username" autocapitalize="off" spellcheck="false" placeholder="\${setup?'3–24 位字母、数字、下划线':'用户名'}" maxlength="24">
 <label class="lb">密码</label><div style="position:relative"><input class="in" id="ap" type="password" autocomplete="\${setup?'new-password':'current-password'}" placeholder="\${setup?'至少 8 位，不能是纯数字':'密码'}" maxlength="128" style="padding-right:64px"><button type="button" id="ae" class="chip" style="position:absolute;right:6px;top:50%;transform:translateY(-50%);padding:4px 11px">显示</button></div>
 \${setup?\`<div class="meter" style="margin-top:10px"><i id="am"></i></div><div style="margin-top:8px" id="ar"></div><label class="lb">确认密码</label><input class="in" id="ap2" type="password" autocomplete="new-password" maxlength="128">\`:''}
 \${!setup&&st.otp?'<label class="lb">两步验证码</label><input class="in" id="ao" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="6 位数字">':''}
 <div class="err" id="ae2"></div><button class="btn lg" id="as" type="submit" \${setup?'disabled':''}>\${setup?'创建并进入':'登录'}</button></form></div></div>\`;
 const lk=$('#lk');if(!st.human)hvInit($('#hvb'),st,()=>{lk.classList.remove('off');$('#hvb').style.cssText='max-height:0;overflow:hidden;opacity:0;transition:all .6s';setTimeout(()=>{$('#hvb').remove();$('#au').focus()},620)});else $('#au').focus();
 const u=$('#au'),p=$('#ap'),btn=$('#as'),er=$('#ae2');$('#ae').onclick=()=>{const s=p.type==='password';p.type=s?'text':'password';if($('#ap2'))$('#ap2').type=p.type;$('#ae').textContent=s?'隐藏':'显示'};
 if(setup){const chk=()=>{const R=pwRules(p.value,u.value),okU=/^[A-Za-z0-9_]{3,24}$/.test(u.value),sc=pwScore(p.value),m=$('#am');m.style.width=(sc/5*100)+'%';m.style.background=sc<=1?'var(--bad)':sc<=3?'var(--warn)':'var(--ok)';$('#ar').innerHTML=[['用户名 3–24 位字母/数字/下划线',okU],...R,['两次密码一致',p.value.length>0&&p.value===$('#ap2').value]].map(r=>\`<div class="chk \${r[1]?'ok':''}"><i>✓</i>\${r[0]}</div>\`).join('');btn.disabled=!(okU&&R.every(r=>r[1])&&p.value===$('#ap2').value)};[u,p,$('#ap2')].forEach(x=>x.addEventListener('input',chk));chk()}
 $('#af').addEventListener('submit',async e=>{e.preventDefault();if(btn.disabled)return;er.textContent='';try{const b={u:u.value.trim(),p:p.value};if(setup&&$('#ac'))b.code=$('#ac').value;if($('#ao'))b.otp=$('#ao').value;await busy(btn,api(setup?'setup':'login',b,{quiet:1}));toast(setup?'账号已创建':'欢迎回来');enter()}catch(x){const m=x&&x.error==='invalid'?'用户名、密码或验证码不正确'+(x.left!=null?\`（还可尝试 \${x.left} 次）\`:''):x&&x.error==='human'?'真人验证已失效，请刷新页面重试':(x&&x.msg)||'登录失败';er.textContent=m;$('#af').parentElement.animate([{transform:'translateX(0)'},{transform:'translateX(-8px)'},{transform:'translateX(8px)'},{transform:'translateX(0)'}],{duration:320});if(x&&x.error==='human')setTimeout(showAuth,1400)}})}
async function enter(){authOk=true;try{ME=await api('me')}catch(e){return}$('#auth').hidden=true;$('#app').hidden=false;buildShell();applyLook(false);
 api('look').then(d=>{if(d&&d.look&&!localStorage.getItem('yt_look_has')){localStorage.setItem('yt_look_has','1');if(d.bg&&!BGDATA){BGDATA=d.bg;try{localStorage.setItem('yt_bgimg',d.bg)}catch(e){}}setLK({...LD,...d.look},false)}else if(d&&d.bg&&!BGDATA){BGDATA=d.bg;applyLook(false)}localStorage.setItem('yt_look_has','1')}).catch(()=>{});
 const h=location.hash.slice(1);cur='';go(P[h]?h:'ov')}

/* ── 通用小组件 ── */
const DUR=[['1','1 小时'],['6','6 小时'],['24','1 天'],['168','7 天'],['720','30 天'],['0','永久']];
const durChips=(id,v)=>\`<div class="chips" id="\${id}" data-v="\${v==null?'0':v}">\${DUR.map(d=>\`<button type="button" class="chip \${String(d[0])===String(v==null?'0':v)?'on':''}" data-pick="\${d[0]}">\${d[1]}</button>\`).join('')}</div>\`;
const REASONS=['作弊 / 滥用','多账号','恶意行为','测试封禁','其他'];
function sync(box,items,keyf,htmlf,o){o=o||{};const have=new Map([...box.children].map(e=>[e.dataset.k,e]));items.forEach((it,i)=>{const k=String(keyf(it)),h=htmlf(it);let e=have.get(k);if(e){have.delete(k);if(e._h!==h){e.innerHTML=h;e._h=h}}else{e=document.createElement('div');e.dataset.k=k;e.className=o.cls||'';e.innerHTML=h;e._h=h;if(o.anim!==false&&LK.anim)e.style.animation='zoomIn calc(.45s*var(--t)) var(--ease) both'}if(box.children[i]!==e)box.insertBefore(e,box.children[i]||null)});have.forEach(e=>e.remove())}
const SKEL6=Array.from({length:6},()=>'<div class="card g stat"><div class="sk-l" style="width:50%"></div><div class="sk-l" style="width:35%;height:30px;margin-top:12px"></div></div>').join('');
const fpsC=f=>f>=50?'var(--ok)':f>=30?'var(--warn)':'var(--bad)',pingC=p=>p<=100?'var(--ok)':p<=220?'var(--warn)':'var(--bad)';
const DV={pc:'电脑',mobile:'手机',console:'主机'};
let PN={};
const pname=(id)=>PN[id]?esc(PN[id]):esc(id);
const placeLink=id=>id?\`<span title="PlaceId \${esc(id)}">\${pname(id)}</span>\`:'—';

/* ── 概览 ── */
P.ov={t:'概览',r(c){let D=null,range=14,cfg=null;
 c.innerHTML=\`<div id="ovb"></div><div class="grid" id="s6" style="--gm:200px">\${SKEL6}</div><div class="g2"><div class="card g"><h2>执行趋势<span class="sp"></span>\${seg('rg',[['7','7 天'],['14','14 天'],['30','30 天']],14)}</h2><div id="c1" style="min-height:210px"></div></div><div class="card g"><h2>最近 24 小时</h2><div id="c2" style="min-height:170px"></div></div></div><div class="g2"><div class="card g"><h2>热门游戏</h2><div id="h1"></div></div><div class="card g"><h2>执行器</h2><div id="d1"></div></div></div><div class="g2"><div class="card g"><h2>设备类型</h2><div id="d2"></div></div><div class="card g"><h2>国家 / 地区</h2><div id="h2"></div></div></div><div class="g2"><div class="card g"><h2>脚本版本</h2><div id="h3"></div></div><div class="card g"><h2>事件类型</h2><div id="h4"></div></div></div><div class="card g"><h2>最近活动<span class="sp"></span><button class="btn ghost sm" id="mo">查看全部日志</button></h2><div id="fd"></div></div>\`;
 post(c);stagger(c);
 const days=n=>Array.from({length:n},(_,i)=>new Date(Date.now()-(n-1-i)*864e5).toISOString().slice(0,10));
 const build=()=>{const d=D,td=new Date().toISOString().slice(0,10),dd=days(14),sp=o=>dd.map(k=>o[k]||0);
  const cards=[['在线','online',d.online,'var(--ok)','on',null],['今日执行','days',d.days[td]||0,'var(--accent)','lg',sp(d.days)],['玩家总数','players',d.players,'#bf5af2','pl',null],['今日活跃','dau',d.dau[td]||0,'#ff9f0a','pl',sp(d.dau)],['今日新增','newp',d.newp[td]||0,'#64d2ff','pl',sp(d.newp)],['可疑设备','susp',d.susp,'var(--bad)','hw',null]];
  const s6=$('#s6');if(!s6.dataset.b){s6.dataset.b=1;s6.innerHTML=cards.map((x,i)=>\`<div class="card g stat tl" data-go="\${x[4]}" style="--i:\${i}"><div class="k"><i style="background:\${x[3]}"></i>\${x[0]}</div><div class="v num" id="sv\${i}">0</div><div class="d" id="sd\${i}"></div>\${x[5]?spark(x[5],x[3]):''}</div>\`).join('');s6.onclick=e=>{const k=e.target.closest('[data-go]');if(k)go(k.dataset.go)}}
  cards.forEach((x,i)=>{cnt($('#sv'+i),x[2])});$('#sd2').textContent='累计执行 '+fmt(d.logs);$('#sd5').textContent='累计设备 '+fmt(d.hwids);$('#sd0').textContent='近 3 分钟有心跳';
  chart();
  const t=new Date().toISOString().slice(0,13),hk=Array.from({length:24},(_,i)=>new Date(Date.now()-(23-i)*36e5).toISOString().slice(0,13));barChart($('#c2'),{labels:hk.map(k=>new Date(k+':00:00Z').getHours()+'时'),vals:hk.map(k=>d.hrs[k]||0)});
  PN=d.pn||PN;const pl=Object.entries(d.places).sort((a,b)=>b[1]-a[1]).slice(0,8);$('#h1').innerHTML=hbars(pl,k=>esc(d.pn[k]||k));
  donut($('#d1'),Object.entries(d.execs).sort((a,b)=>b[1]-a[1]).slice(0,7).map(x=>({n:x[0],v:x[1]})));donut($('#d2'),Object.entries(d.devs||{}).map(x=>({n:DV[x[0]]||'未知',v:x[1]})));
  $('#h2').innerHTML=hbars(Object.entries(d.countries).sort((a,b)=>b[1]-a[1]).slice(0,8),k=>flag(k)+' '+esc(k));$('#h3').innerHTML=hbars(Object.entries(d.vers).sort((a,b)=>b[1]-a[1]).slice(0,6));$('#h4').innerHTML=hbars(Object.entries(d.actions).sort((a,b)=>b[1]-a[1]).slice(0,8));post($('#h1').parentElement.parentElement.parentElement);post(c);
  feed()};
 const chart=()=>{const dd=days(range);areaChart($('#c1'),{labels:dd.map(k=>k.slice(5)),series:[{name:'执行',color:'#0a84ff',vals:dd.map(k=>D.days[k]||0)},{name:'活跃',color:'#ff9f0a',vals:dd.map(k=>D.dau[k]||0)},{name:'新增',color:'#30d158',vals:dd.map(k=>D.newp[k]||0)}]})};
 const feed=()=>{$('#fd').innerHTML=D.recent.length?D.recent.map(r=>\`<div class="row" data-u="\${esc(r.i)}">\${av(r.u)}<div class="grow"><b>\${esc(r.u)}</b><span>\${esc(r.a)} · \${placeLink(r.p)}</span></div><div class="end">\${ago(r.t)}</div></div>\`).join(''):emptyBox('还没有执行记录','让脚本跑起来后这里会实时更新')};
 const banner=()=>{const b=$('#ovb');if(!cfg||!b)return;let h='';if(cfg.kill)h+=\`<div class="banner"><b>紧急停用已开启：所有客户端正在被断开</b><button class="btn ghost sm" id="kx">关闭停用</button></div>\`;if(cfg.wlRequired)h+=\`<div class="banner warn"><b>当前为“仅白名单可用”模式</b><button class="btn ghost sm" id="wx">前往白名单</button></div>\`;b.innerHTML=h;const kx=$('#kx');if(kx)kx.onclick=async()=>{try{await api('cfg',{kill:false});cfg.kill=false;toast('已关闭紧急停用');banner()}catch(e){err(e)}};const wx=$('#wx');if(wx)wx.onclick=()=>go('wl')};
 const load=async()=>{try{[D,cfg]=await Promise.all([api('stats'),api('cfg')]);build();banner()}catch(e){if(!D)err(e)}};
 $('#rg').addEventListener('chg',e=>{range=+e.detail;if(D)chart()});$('#mo').onclick=()=>go('lg');$('#fd').onclick=e=>{const r=e.target.closest('[data-u]');if(r)pSheet(r.dataset.u)};
 c._t=load;load()}};

/* ── 在线 ── */
P.on={t:'实时在线',r(c){let L=[],sel=new Set(),selMode=false,fl={q:'',pl:'',so:'t'};
 c.innerHTML=\`<div class="bar"><input class="in grow" id="q" placeholder="筛选玩家名 / UserId"><select class="in" id="pf" style="width:auto;min-width:130px"><option value="">所有游戏</option></select>\${seg('so',[['t','最近'],['f','FPS'],['p','延迟']],'t')}<button class="btn ghost" id="sm">多选</button></div><div id="ons" class="sub" style="margin:-6px 4px 12px"></div><div class="grid" id="gr" style="--gm:270px"></div>\`;post(c);stagger(c);
 const gr=$('#gr'),card=p=>\`<div class="tp">\${av(p.u)}<div style="min-width:0;flex:1"><b style="display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">\${esc(p.u)}</b><span class="sub">\${placeLink(p.p)}</span></div><div style="text-align:right"><div style="color:\${fpsC(p.f)};font-weight:700" class="num">\${p.f||'—'}<small style="font-weight:500;opacity:.7"> fps</small></div><div class="sub num" style="color:\${p.pg?pingC(p.pg):'inherit'}">\${p.pg?p.pg+' ms':'—'}</div></div></div><div class="m"><span>\${flag(p.c)} \${esc(p.c||'??')}</span><span>\${DV[p.dv]||'未知设备'}</span>\${p.m?\`<span>\${p.m} MB</span>\`:''}<span>\${ago(p.t)}</span></div>\`;
 const draw=()=>{const q=fl.q.toLowerCase();let a=L.filter(p=>(!q||p.u.toLowerCase().includes(q)||p.i.includes(q))&&(!fl.pl||p.p===fl.pl));a.sort((x,y)=>fl.so==='f'?(x.f||999)-(y.f||999):fl.so==='p'?(y.pg||0)-(x.pg||0):y.t-x.t);
  $('#ons').textContent=\`\${L.length} 人在线\${a.length!==L.length?'，筛选后 '+a.length+' 人':''}\${L.length?' · 平均 '+Math.round(L.reduce((s,p)=>s+(p.f||0),0)/Math.max(1,L.filter(p=>p.f).length))+' FPS':''}\`;
  if(!a.length){gr.innerHTML=emptyBox('现在没有人在线','玩家运行脚本后会出现在这里');gr._e=1}else{if(gr._e){gr.innerHTML='';gr._e=0}sync(gr,a,p=>p.i,card,{cls:'card g pc tl'});[...gr.children].forEach(e=>e.classList.toggle('sel',sel.has(e.dataset.k)))}
  const bk=$('#bulk');bk.classList.toggle('on',selMode&&sel.size>0);if(selMode&&sel.size)bk.innerHTML=\`<b>已选 \${sel.size}</b><button class="btn sm" data-b="notify">通知</button><button class="btn sm" data-b="msg">消息</button><button class="btn sm ghost" data-b="teleport">传送</button><button class="btn sm ghost" data-b="wl">加白名单</button><button class="btn sm red" data-b="kick">踢出</button><button class="btn sm red" data-b="ban">封禁</button><button class="btn sm ghost" data-b="x">取消</button>\`;
  const ps=[...new Set(L.map(p=>p.p))];const ps0=$('#pf'),v=ps0.value;ps0.innerHTML='<option value="">所有游戏</option>'+ps.map(x=>\`<option value="\${esc(x)}">\${pname(x)}</option>\`).join('');ps0.value=ps.includes(v)?v:''};
 const load=async()=>{try{const d=await api('online');PN={...PN,...d.pn};L=d.list;draw();const b=$('.nv[data-p=on] .bdg');$$('.nv[data-p=on] .bdg').forEach(b=>{b.hidden=!L.length;b.textContent=L.length})}catch(e){if(!L.length)err(e)}};
 $('#q').addEventListener('input',e=>{fl.q=e.target.value;draw()});$('#pf').addEventListener('change',e=>{fl.pl=e.target.value;draw()});$('#so').addEventListener('chg',e=>{fl.so=e.detail;draw()});
 $('#sm').onclick=()=>{selMode=!selMode;sel.clear();$('#sm').textContent=selMode?'退出多选':'多选';$('#sm').classList.toggle('ghost',!selMode);draw()};
 gr.onclick=e=>{const k=e.target.closest('[data-k]');if(!k)return;if(selMode){sel.has(k.dataset.k)?sel.delete(k.dataset.k):sel.add(k.dataset.k);hap(6);draw()}else pSheet(k.dataset.k)};
 $('#bulk').onclick=e=>{const b=e.target.closest('[data-b]');if(!b)return;if(b.dataset.b==='x'){sel.clear();draw()}else bulkSheet(b.dataset.b,[...sel],()=>{sel.clear();load()})};
 c._t=load;c._x=()=>$('#bulk').classList.remove('on');load()}};
function bulkSheet(op,ids,done){const T={notify:['发送通知','通知内容'],msg:['发送消息','消息内容'],teleport:['传送到游戏','PlaceId（数字）'],kick:['踢出玩家','踢出提示'],ban:['封禁玩家',''],wl:['加入白名单','']}[op];
 sheet(\`<h2>\${T[0]} · \${ids.length} 人</h2>\${op==='ban'?\`<label class="lb">原因</label><input class="in" id="br" placeholder="封禁原因"><div class="chips" style="margin-top:8px" id="rs">\${REASONS.map(r=>\`<button type="button" class="chip" data-r="\${r}">\${r}</button>\`).join('')}</div><label class="lb">时长</label>\${durChips('bd','0')}<div class="fl"><div><b>同时封禁设备</b><div class="sub">封禁这些玩家最近使用的设备</div></div>\${sw('bdv',false,'rd')}</div>\`:op==='wl'?\`<label class="lb">有效期</label>\${durChips('bd','0')}\`:\`<input class="in" id="bm" placeholder="\${T[1]}">\`}<div class="bar" style="margin:18px 0 0"><button class="btn \${op==='ban'||op==='kick'?'red':''}" id="go">确认</button><button class="btn ghost" id="no">取消</button></div>\`,s=>{if(op==='ban')$('#rs').onclick=e=>{const r=e.target.closest('[data-r]');if(r)$('#br').value=r.dataset.r};$('#no').onclick=shut;$('#go').onclick=async()=>{const b=$('#go');try{let body;if(op==='ban')body={op:'ban',ids,reason:$('#br').value||'banned',hours:+$('#bd').dataset.v,device:$('#bdv').checked};else if(op==='wl')body={op:'wl',ids,hours:+$('#bd').dataset.v};else{const m=$('#bm').value.trim();if(op==='teleport'&&!/^\\d+$/.test(m))return toast('请填写 PlaceId','bad');if((op==='notify'||op==='msg')&&!m)return toast('请输入内容','bad');body={op:'cmd',ids,c:op,m}}const r=await busy(b,api('bulk',body));toast(\`已对 \${r.n} 人执行\`);shut();done&&done()}catch(e){err(e)}}})}

/* ── 玩家 ── */
P.pl={t:'玩家',r(c){let q='',flt='all',inf=null;
 c.innerHTML=\`<div class="bar"><input class="in grow" id="q" placeholder="搜索游戏名或 UserId（前缀匹配）" autocomplete="off">\${seg('fl',[['all','全部'],['sus','可疑'],['ban','已封禁'],['tag','有标签']],'all')}</div><div class="card g" style="padding:8px 12px"><div id="ls"></div></div>\`;post(c);stagger(c);
 const ls=$('#ls'),ok=p=>flt==='all'||(flt==='sus'&&p.sus)||(flt==='ban'&&p.ban)||(flt==='tag'&&(p.tags||[]).length);
 const row=p=>\`<div class="row" data-u="\${esc(p.userId)}">\${av(p.user)}<div class="grow"><b>\${esc(p.user)}\${p.dn&&p.dn!==p.user?\` <small class="mut">\${esc(p.dn)}</small>\`:''}</b><span>\${esc(p.userId)} · \${flag(p.cc)} \${esc(p.ex||'')} · \${fmt(p.n)} 次</span></div><div class="end">\${p.ban?'<span class="tag bad">封禁</span>':''}\${p.sus?'<span class="tag warn">可疑</span>':''}\${(p.tags||[]).slice(0,2).map(t=>\`<span class="tag ac">\${esc(t)}</span>\`).join('')}<div>\${ago(p.last)}</div></div></div>\`;
 const start=()=>{if(inf)inf.stop();ls.innerHTML='';inf=infinite(ls,async cur=>{const d=await api('players?q='+encodeURIComponent(q)+(cur?'&cursor='+encodeURIComponent(cur):''));const a=d.players.filter(ok);ls.insertAdjacentHTML('beforeend',a.map(row).join(''));if(!ls.children.length&&!d.cursor)ls.innerHTML=emptyBox('没有找到玩家',q?'试试 UserId，或检查拼写':'');return{cursor:d.cursor,empty:!ls.children.length}})};
 $('#q').addEventListener('input',debounce(e=>{q=e.target.value.trim();start()},320));$('#fl').addEventListener('chg',e=>{flt=e.detail;start()});
 ls.onclick=e=>{const r=e.target.closest('[data-u]');if(r)pSheet(r.dataset.u)};c._x=()=>inf&&inf.stop();start()}};
async function pAct(path,body,msg,id){try{await api(path,body);toast(msg||'已完成');if(id)pSheet(id,1)}catch(e){err(e)}}
function banSheet(id,name,nHw,back){sheet(\`<h2>封禁 \${esc(name)}</h2><label class="lb">原因（玩家会看到）</label><input class="in" id="br" placeholder="例如：使用外挂" maxlength="80"><div class="chips" style="margin-top:8px" id="rs">\${REASONS.map(r=>\`<button type="button" class="chip" data-r="\${r}">\${r}</button>\`).join('')}</div><label class="lb">时长</label>\${durChips('bd','0')}<div class="fl"><div><b>同时封禁设备</b><div class="sub" id="dv">封禁该玩家最近的 \${nHw} 个设备 ID，换号也无法进入</div></div>\${sw('bdv',false,'rd')}</div><div class="dep off" id="dw"><div><div class="banner warn" style="margin:6px 0 0"><b>设备封禁会影响同一台设备上的所有账号，请确认没有误伤</b></div></div></div><div class="bar" style="margin:18px 0 0"><button class="btn red" id="go">确认封禁</button><button class="btn ghost" id="no">返回</button></div>\`,s=>{$('#rs').onclick=e=>{const r=e.target.closest('[data-r]');if(r){$('#br').value=r.dataset.r;$$('#rs .chip').forEach(x=>x.classList.toggle('on',x===r))}};$('#bdv').onchange=e=>$('#dw').classList.toggle('off',!e.target.checked);$('#no').onclick=()=>pSheet(id);$('#go').onclick=async()=>{try{await busy($('#go'),api('ban',{userId:id,reason:$('#br').value||'banned',hours:+$('#bd').dataset.v,device:$('#bdv').checked}));toast('已封禁');pSheet(id,1)}catch(e){err(e)}}})}
function wlSheet(id,name){sheet(\`<h2>加入白名单 · \${esc(name)}</h2><label class="lb">有效期</label>\${durChips('bd','0')}<div class="bar" style="margin:18px 0 0"><button class="btn" id="go">加入</button><button class="btn ghost" id="no">返回</button></div>\`,s=>{$('#no').onclick=()=>pSheet(id);$('#go').onclick=()=>busy($('#go'),api('wl',{userId:id,hours:+$('#bd').dataset.v})).then(()=>{toast('已加入白名单');pSheet(id,1)}).catch(err)})}
async function pSheet(id,keep){let p;try{p=await api('player/'+encodeURIComponent(id))}catch(e){return err(e)}
 const nm=p.user,om=p.om,tabs=[['a','概览'],['c','指令'],['d','设备 / IP'],['f','专属开关'],['n','备注标签']];
 const html=\`<div style="display:flex;gap:14px;align-items:center;margin-bottom:12px">\${av(nm,'lgx')}<div style="min-width:0;flex:1"><h2 style="margin:0">\${esc(nm)}</h2><div class="sub">\${p.dn&&p.dn!==nm?esc(p.dn)+' · ':''}<span class="mono" id="cid" style="cursor:pointer" title="点击复制">\${esc(p.userId)}</span></div><div style="margin-top:6px">\${p.online?'<span class="tag ok">在线</span>':''}\${p.wl?\`<span class="tag ok">白名单 · \${left(p.wlx)}</span>\`:''}\${p.banInfo?\`<span class="tag bad">封禁 · \${esc(p.banInfo.r)} · \${left(p.banInfo.e)}</span>\`:''}\${p.sus?'<span class="tag warn">多账号可疑</span>':''}\${(p.tags||[]).map(t=>\`<span class="tag ac">\${esc(t)}</span>\`).join('')}</div></div></div>
 <div class="chips" style="margin-bottom:14px">\${p.banInfo?'<button class="chip" id="a-ub">解封</button>':'<button class="chip" id="a-b" style="color:var(--bad)">封禁…</button>'}\${p.wl?'<button class="chip" id="a-uw">移出白名单</button>':'<button class="chip" id="a-w">加入白名单…</button>'}<a class="chip" href="https://www.roblox.com/users/\${esc(p.userId)}/profile" target="_blank" rel="noopener noreferrer" style="text-decoration:none">Roblox 主页</a></div>
 \${seg('pt',tabs,'a')}<div id="pp" style="margin-top:14px"></div>\`;
 const pane={
 a:()=>\`<div class="kvs"><div><small>执行次数</small><b>\${fmt(p.n)}</b></div><div><small>首次出现</small><b>\${dt(p.first)}</b></div><div><small>最近活动</small><b>\${ago(p.last)}</b></div><div><small>账号年龄</small><b>\${fmt(p.ag)} 天</b></div><div><small>地区</small><b>\${flag(p.cc)} \${esc(p.cc||'—')}</b></div><div><small>执行器</small><b>\${esc(p.ex||'—')}</b></div><div><small>设备</small><b>\${DV[p.dv]||'—'}</b></div><div><small>当前游戏</small><b>\${om?placeLink(om.p):'—'}</b></div>\${om?\`<div><small>FPS / 延迟</small><b>\${om.f||'—'} / \${om.pg||'—'} ms</b></div>\`:''}</div>\${p.note?\`<div class="banner warn" style="margin:0 0 12px"><b>备注：\${esc(p.note)}</b></div>\`:''}<h2 style="font-size:1em;margin:14px 0 4px">最近事件</h2>\${(p.ev||[]).length?p.ev.map(e=>\`<div class="tl-i"><i></i><div>\${esc(e.a)} · \${placeLink(e.p)}</div><span class="t">\${ago(e.t)}</span></div>\`).join(''):'<div class="sub">暂无</div>'}\${p.alts.length?\`<h2 style="font-size:1em;margin:16px 0 4px">同设备的其他账号（\${p.alts.length}）</h2>\${p.alts.map(a=>\`<div class="row" data-u="\${esc(a.userId)}">\${av(a.user)}<div class="grow"><b>\${esc(a.user)}</b><span>\${esc(a.userId)}</span></div><div class="end">\${a.ban?'<span class="tag bad">封禁</span>':''}</div></div>\`).join('')}\`:''}\`,
 c:()=>\`<div class="sub" style="margin-bottom:10px">指令会在对方客户端下一次心跳（约 \${Math.round(P_POLL)} 秒内）执行\${p.online?'':'；该玩家当前不在线，指令最多保留 1 小时'}。</div><label class="lb">通知 / 消息</label><div class="bar" style="margin:0"><input class="in grow" id="cm" placeholder="内容" maxlength="200"><button class="btn sm" data-c="notify">通知</button><button class="btn sm ghost" data-c="msg">消息</button></div><label class="lb">传送到 PlaceId</label><div class="bar" style="margin:0"><input class="in grow" id="ct" inputmode="numeric" placeholder="PlaceId"><button class="btn sm ghost" data-c="teleport">传送</button></div><label class="lb">其他</label><div class="chips"><button class="chip" data-c="rejoin">重新加入</button><button class="chip" data-c="ping">立即同步</button><button class="chip" data-c="reload">重载脚本</button><button class="chip" data-c="kick" style="color:var(--bad)">踢出</button></div>\`,
 d:()=>\`<h2 style="font-size:1em;margin:0 0 4px">设备 ID（\${(p.hw||[]).length}）</h2>\${(p.hw||[]).length?p.hw.map(h=>\`<div class="row" data-h="\${esc(h)}"><div class="grow"><b class="mono">\${esc(h.slice(0,28))}…</b></div><div class="end">查看 ›</div></div>\`).join(''):'<div class="sub">暂无</div>'}<h2 style="font-size:1em;margin:16px 0 4px">最近 IP（\${(p.ips||[]).length}）</h2>\${(p.ips||[]).map(i=>\`<div class="row" style="cursor:default"><div class="grow"><b class="mono">\${esc(i)}</b></div><button class="btn sm ghost" data-ip="\${esc(i)}">封禁 IP</button></div>\`).join('')||'<div class="sub">暂无</div>'}\`,
 f:()=>\`<div class="sub" style="margin-bottom:10px">只对这位玩家生效，会覆盖全局开关；清空值即删除。</div>\${Object.keys(p.pf).length?Object.entries(p.pf).map(([k,v])=>\`<div class="kv" style="grid-template-columns:1fr 1fr auto"><div class="in mono">\${esc(k)}</div><div class="in mono">\${esc(JSON.stringify(v))}</div><button class="btn sm ghost" data-df="\${esc(k)}">删除</button></div>\`).join(''):'<div class="sub" style="margin:8px 0">还没有专属开关</div>'}<label class="lb">添加 / 修改</label><div class="kv"><input class="in" id="fk" placeholder="名称，如 speed"><input class="in" id="fv" placeholder="值，如 32 / true"><button class="btn sm" id="fa">保存</button></div>\`,
 n:()=>\`<label class="lb">备注（仅你可见）</label><textarea class="in" id="nt" maxlength="300">\${esc(p.note||'')}</textarea><label class="lb">标签（最多 5 个）</label><div class="chips" id="tg"></div><div class="bar" style="margin:10px 0 0"><input class="in grow" id="tn" maxlength="12" placeholder="新标签，回车添加"></div><div style="margin-top:14px"><button class="btn" id="ns">保存备注和标签</button></div>\`};
 sheet(html,s=>{const pp=$('#pp');let tags=[...(p.tags||[])];const show=k=>{pp.style.opacity=0;setTimeout(()=>{pp.innerHTML=pane[k]();pp.style.opacity=1;post(pp);bindP(k)},120)};pp.style.transition='opacity .12s';
  const bindP=k=>{if(k==='a')pp.onclick=e=>{const r=e.target.closest('[data-u]');if(r)pSheet(r.dataset.u)};
   if(k==='c'){pp.onclick=async e=>{const b=e.target.closest('[data-c]');if(!b)return;const c=b.dataset.c;let m='';if(c==='notify'||c==='msg'){m=$('#cm').value.trim();if(!m)return toast('请输入内容','bad')}if(c==='teleport'){m=$('#ct').value.trim();if(!/^\\d+$/.test(m))return toast('请填写 PlaceId','bad')}if(c==='kick'){m=$('#cm')?$('#cm').value.trim():'';if(!await danger({t:'踢出 '+nm+'？',m:'玩家会立刻被断开。',ok:'踢出'},()=>pSheet(id,1)))return}try{await api('cmd',{userId:id,c,m});toast('指令已排队')}catch(x){err(x)}}}
   if(k==='d')pp.onclick=async e=>{const h=e.target.closest('[data-h]'),i=e.target.closest('[data-ip]');if(h)hwSheet(h.dataset.h,()=>pSheet(id,1));if(i&&await danger({t:'封禁 IP '+i.dataset.ip+'？',m:'使用这个 IP 的所有玩家都会无法进入。',ok:'封禁 IP'},()=>pSheet(id,1))){try{await api('ipban',{ip:i.dataset.ip,reason:'与 '+nm+' 同 IP'});toast('已封禁 IP')}catch(x){err(x)}pSheet(id,1)}};
   if(k==='f'){pp.onclick=e=>{const d=e.target.closest('[data-df]');if(d)pAct('pflag',{userId:id,k:d.dataset.df,v:''},'已删除',id)};$('#fa').onclick=()=>{const k=$('#fk').value.trim();if(!k)return toast('请填写名称','bad');pAct('pflag',{userId:id,k,v:$('#fv').value.trim()},'已保存',id)}}
   if(k==='n'){const dt2=()=>{$('#tg').innerHTML=tags.map((t,i)=>\`<span class="chip x on">\${esc(t)}<b data-i="\${i}">×</b></span>\`).join('')||'<span class="sub">还没有标签</span>'};dt2();$('#tg').onclick=e=>{const b=e.target.closest('[data-i]');if(b){tags.splice(+b.dataset.i,1);dt2()}};$('#tn').onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();const v=e.target.value.trim();if(v&&tags.length<5&&!tags.includes(v)){tags.push(v);e.target.value='';dt2()}}};$('#ns').onclick=async()=>{try{await api('note',{userId:id,note:$('#nt').value});await api('tags',{userId:id,tags});toast('已保存')}catch(x){err(x)}}}};
  $('#pt').addEventListener('chg',e=>show(e.detail));pp.innerHTML=pane.a();bindP('a');$('#cid').onclick=()=>copy(p.userId);
  const A=(i,f)=>{const b=$('#'+i);if(b)b.onclick=f};A('a-b',()=>banSheet(id,nm,(p.hw||[]).length));A('a-w',()=>wlSheet(id,nm));
  A('a-ub',()=>pAct('unban',{userId:id},'已解封',id));A('a-uw',()=>pAct('unwl',{userId:id},'已移出白名单',id))},true)}
let P_POLL=10;
async function hwSheet(h,back){let d;try{d=await api('hwid/'+encodeURIComponent(h))}catch(e){return err(e)}
 sheet(\`<h2>设备</h2><div class="mono" style="word-break:break-all;color:var(--fg2)">\${esc(h)}</div><div style="margin:10px 0">\${d.banned?\`<span class="tag bad">已封禁 · \${esc(d.ban.r)} · \${left(d.ban.e)}</span>\`:'<span class="tag ok">正常</span>'}<span class="tag">\${d.accounts.length} 个账号</span></div>\${d.accounts.map(a=>\`<div class="row" data-u="\${esc(a.userId)}">\${av(a.user)}<div class="grow"><b>\${esc(a.user)}</b><span>\${esc(a.userId)} · \${ago(a.last)}</span></div><div class="end">\${a.ban?'<span class="tag bad">封禁</span>':''}</div></div>\`).join('')}<div class="bar" style="margin:16px 0 0">\${d.banned?'<button class="btn" id="hu">解封设备</button>':'<button class="btn red" id="hb">封禁此设备</button>'}<button class="btn ghost" id="hx">关闭</button></div>\`,s=>{s.onclick=e=>{const r=e.target.closest('[data-u]');if(r)pSheet(r.dataset.u)};$('#hx').onclick=()=>back?back():shut();const hu=$('#hu'),hb=$('#hb');if(hu)hu.onclick=()=>api('unhwban',{hwid:h}).then(()=>{toast('已解封');hwSheet(h,back)}).catch(err);if(hb)hb.onclick=async()=>{if(!await danger({t:'封禁这台设备？',m:\`该设备上的 \${d.accounts.length} 个账号都将无法进入。\`,ok:'封禁设备'},()=>hwSheet(h,back)))return;api('hwban',{hwid:h,reason:'设备封禁'}).then(()=>{toast('已封禁设备');hwSheet(h,back)}).catch(err)}})}

/* ── 日志 ── */
const ACOL={execute:'var(--ok)',teleport:'var(--accent)',error:'var(--bad)'};
P.lg={t:'执行日志',r(c){let q='',act='',inf=null,live=null,top='';
 c.innerHTML=\`<div class="bar"><input class="in grow" id="q" placeholder="筛选玩家 / 事件 / PlaceId（已加载的内容中）"><label class="live" style="gap:9px">实时追加\${sw('lv',false)}</label><a class="btn ghost" href="/api/export" download>导出 CSV</a></div><div class="chips" id="ac" style="margin-bottom:14px"></div><div class="card g" style="padding:8px 12px"><div id="ls"></div></div>\`;post(c);stagger(c);
 const ls=$('#ls'),seen=new Set(),acts=new Set(),row=x=>\`<div class="row" data-k="\${esc(x.k)}"><i class="dotx" style="background:\${ACOL[x.a]||'var(--fg3)'};margin:0"></i><div class="grow"><b>\${esc(x.u)} <small class="mut">\${esc(x.a)}</small></b><span>\${placeLink(x.p)}\${x.v?' · v'+esc(x.v):''}</span></div><div class="end">\${dt(x.t)}<div>\${ago(x.t)}</div></div></div>\`;
 const vis=x=>(!act||x.a===act)&&(!q||(x.u+' '+x.a+' '+x.p+' '+x.i).toLowerCase().includes(q));const store=[];
 const chips=()=>{$('#ac').innerHTML=\`<button class="chip \${act?'':'on'}" data-a="">全部</button>\`+[...acts].map(a=>\`<button class="chip \${act===a?'on':''}" data-a="\${esc(a)}">\${esc(a)}</button>\`).join('')};
 const redraw=()=>{ls.innerHTML=store.filter(vis).map(row).join('')||emptyBox('没有符合条件的日志')};
 const start=()=>{if(inf)inf.stop();store.length=0;ls.innerHTML='';inf=infinite(ls,async cur=>{const d=await api('logs'+(cur?'?cursor='+encodeURIComponent(cur):''));d.logs.forEach(x=>{if(!seen.has(x.k)){seen.add(x.k);store.push(x);acts.add(x.a)}});chips();ls.insertAdjacentHTML('beforeend',d.logs.filter(vis).map(row).join(''));if(!store.length&&!d.cursor)ls.innerHTML=emptyBox('还没有日志');return{cursor:d.cursor,empty:!store.length}})};
 $('#q').addEventListener('input',debounce(e=>{q=e.target.value.trim().toLowerCase();redraw()},200));$('#ac').onclick=e=>{const b=e.target.closest('[data-a]');if(b){act=b.dataset.a;chips();redraw()}};
 $('#lv').onchange=e=>{clearInterval(live);if(e.target.checked){live=setInterval(async()=>{try{const d=await api('logs');const nw=d.logs.filter(x=>!seen.has(x.k));if(nw.length){nw.forEach(x=>{seen.add(x.k);acts.add(x.a)});store.unshift(...nw);chips();ls.insertAdjacentHTML('afterbegin',nw.filter(vis).map(row).join(''));toast('+'+nw.length+' 条新日志')}}catch(x){}},4000)}};
 ls.onclick=async e=>{const r=e.target.closest('[data-k]');if(!r)return;try{const d=await api('log?k='+encodeURIComponent(r.dataset.k));let dj='';if(d.d){try{dj=JSON.stringify(JSON.parse(d.d),null,2)}catch(x){dj=d.d}}sheet(\`<h2>\${esc(d.u)} · \${esc(d.a)}</h2><div class="kvs"><div><small>时间</small><b>\${dt(d.t)}</b></div><div><small>UserId</small><b>\${esc(d.i)}</b></div><div><small>游戏</small><b>\${placeLink(d.p)}</b></div><div><small>版本</small><b>\${esc(d.v||'—')}</b></div><div><small>地区 / IP</small><b>\${flag(d.c)} \${esc(d.ip||'')}</b></div><div><small>执行器</small><b>\${esc(d.x||'—')}</b></div></div>\${dj?\`<label class="lb">附带数据</label><pre class="in mono" style="white-space:pre-wrap;word-break:break-all;margin:0">\${esc(dj)}</pre>\`:''}<div class="bar" style="margin:16px 0 0"><button class="btn" id="lp">查看玩家</button><button class="btn ghost" id="lx">关闭</button></div>\`,s=>{$('#lp').onclick=()=>pSheet(d.i);$('#lx').onclick=shut})}catch(x){err(x)}};
 c._x=()=>{inf&&inf.stop();clearInterval(live)};start()}};

/* ── 封禁 ── */

/* ── 脚本错误日志 ── */
P.er={t:'错误日志',r(c){let q='',list=[];
 c.innerHTML=\`<div class="bar"><input class="in grow" id="q" placeholder="搜索：玩家 / 功能名 / 错误内容"><button class="btn ghost sm" id="rf">刷新</button><button class="btn ghost sm" id="cp">复制全部</button><button class="btn red sm" id="cl">清空</button><span class="sub" id="ct"></span></div><div class="card g" style="padding:8px 12px"><div id="ls">\${skel(5)}</div></div>\`;
 post(c);stagger(c);
 const rows=()=>{const qq=q.toLowerCase();const f=list.filter(x=>!qq||(x.u+x.i+x.fn+x.err+(x.extra||'')).toLowerCase().includes(qq));$('#ct').textContent=f.length+' / '+list.length+' 条';$('#ls').innerHTML=f.length?f.map(x=>\`<div class="tl-i"><i style="background:var(--bad)"></i><div style="min-width:0"><b style="font-weight:600">\${esc(x.fn||'unknown')}</b><div class="sub" style="word-break:break-all"><span class="tag bad">ERROR</span> \${esc(x.u||'')} · \${esc(x.i||'')}\${x.x?' · '+esc(x.x):''}\${x.p?' · Place '+esc(x.p):''}<br><span class="mono">\${esc(x.err||'')}</span>\${x.extra?\`<br><span class="mono" style="opacity:.8">\${esc(x.extra)}</span>\`:''}</div></div><span class="t">\${ago(x.t)}</span></div>\`).join(''):emptyBox('暂无脚本报错','客户端用 pcall 捕获的错误会出现在这里')};
 const load=async()=>{try{const d=await api('errlog');list=d.list||[];rows()}catch(e){err(e)}};
 $('#q').oninput=e=>{q=e.target.value.trim();rows()};$('#rf').onclick=load;
 $('#cp').onclick=()=>{const t=list.map(x=>'['+new Date(x.t).toISOString()+'] '+x.u+'('+x.i+') '+x.fn+': '+x.err).join('\\n');copy(t);toast('已复制 '+list.length+' 条')};
 $('#cl').onclick=async()=>{if(!await danger({t:'清空错误日志？',m:'仅清空脚本错误列表，不影响执行日志。',ok:'清空'}))return;try{await api('errlog/clear',{});list=[];rows();toast('已清空')}catch(e){err(e)}};
 c._t=load;load()}};

P.bn={t:'封禁管理',r(c){let tab='u',D=null,q='';
 c.innerHTML=\`<div class="bar">\${seg('tb',[['u','玩家'],['h','设备'],['i','IP']],'u')}<input class="in grow" id="q" placeholder="搜索"><button class="btn" id="add">新增封禁</button><button class="btn ghost" id="imp">批量导入</button></div><div class="card g" style="padding:8px 12px"><div id="ls">\${skel(5)}</div></div>\`;post(c);stagger(c);
 const rows=()=>{const a=tab==='u'?D.list:tab==='h'?D.dev:D.ips,qq=q.toLowerCase();const f=a.filter(x=>!qq||JSON.stringify(x).toLowerCase().includes(qq)).sort((x,y)=>y.t-x.t);
  $('#ls').innerHTML=f.length?f.map(x=>{const key=tab==='u'?x.i:tab==='h'?x.h:x.ip,title=tab==='u'?(x.u||x.i):tab==='h'?(x.h||'').slice(0,26)+'…':x.ip;return\`<div class="row" data-k="\${esc(key)}">\${tab==='u'?av(x.u||'?'):\`<div class="av" style="background:var(--fill2)">\${tab==='h'?'⌘':'#'}</div>\`}<div class="grow"><b>\${esc(title)}</b><span>\${esc(x.r||'banned')} · \${ago(x.t)}\${tab==='u'?' · '+esc(x.i):''}</span></div><div class="end"><span class="tag \${x.e?'warn':'bad'}">\${x.e?'剩 '+left(x.e):'永久'}</span><button class="btn sm ghost" data-un="\${esc(key)}">解除</button></div></div>\`}).join(''):emptyBox('这里是空的','没有被封禁的'+({u:'玩家',h:'设备',i:'IP'}[tab]))};
 const load=async()=>{try{D=await api('bans');rows()}catch(e){err(e)}};
 $('#tb').addEventListener('chg',e=>{tab=e.detail;rows()});$('#q').addEventListener('input',e=>{q=e.target.value.trim();if(D)rows()});
 $('#ls').onclick=async e=>{const u=e.target.closest('[data-un]'),r=e.target.closest('[data-k]');if(u){e.stopPropagation();const k=u.dataset.un;if(!await danger({t:'解除封禁？',m:k,ok:'解除'}))return;try{await api(tab==='u'?'unban':tab==='h'?'unhwban':'unipban',tab==='u'?{userId:k}:tab==='h'?{hwid:k}:{ip:k});toast('已解除');load()}catch(x){err(x)}}else if(r){if(tab==='u')pSheet(r.dataset.k);else if(tab==='h')hwSheet(r.dataset.k)}};
 $('#add').onclick=()=>{const L={u:['玩家名或 UserId','输入游戏名或数字 ID'],h:['设备 ID（HWID）','粘贴 HWID'],i:['IP 地址','例如 203.0.113.9']}[tab];sheet(\`<h2>新增封禁 · \${({u:'玩家',h:'设备',i:'IP'})[tab]}</h2><label class="lb">\${L[0]}</label><input class="in" id="bt" placeholder="\${L[1]}" autocomplete="off"><label class="lb">原因</label><input class="in" id="br" maxlength="80" placeholder="封禁原因"><div class="chips" style="margin-top:8px" id="rs">\${REASONS.map(r=>\`<button type="button" class="chip" data-r="\${r}">\${r}</button>\`).join('')}</div><label class="lb">时长</label>\${durChips('bd','0')}\${tab==='u'?\`<div class="fl"><div><b>同时封禁设备</b><div class="sub">玩家换号也进不来</div></div>\${sw('bdv',false,'rd')}</div>\`:''}<div class="bar" style="margin:18px 0 0"><button class="btn red" id="go">封禁</button><button class="btn ghost" id="no">取消</button></div>\`,s=>{$('#rs').onclick=e=>{const r=e.target.closest('[data-r]');if(r)$('#br').value=r.dataset.r};$('#no').onclick=shut;$('#bt').focus();$('#go').onclick=async()=>{const t=$('#bt').value.trim();if(!t)return toast('请填写目标','bad');const body=tab==='u'?{userId:t,device:$('#bdv').checked}:tab==='h'?{hwid:t}:{ip:t};body.reason=$('#br').value||'banned';body.hours=+$('#bd').dataset.v;try{await busy($('#go'),api(tab==='u'?'ban':tab==='h'?'hwban':'ipban',body));toast('已封禁');shut();load()}catch(x){err(x)}}})};
 $('#imp').onclick=()=>sheet(\`<h2>批量封禁玩家</h2><div class="sub">每行一个玩家名或 UserId，可混用。</div><textarea class="in mono" id="bl" style="min-height:150px;margin-top:10px" placeholder="123456789\\nSomeUser"></textarea><label class="lb">原因</label><input class="in" id="br" maxlength="80" value="批量封禁"><label class="lb">时长</label>\${durChips('bd','0')}<div class="meter" style="margin-top:16px"><i id="pg" style="background:var(--accent)"></i></div><div class="sub" id="pt" style="margin-top:6px"></div><div class="bar" style="margin:16px 0 0"><button class="btn red" id="go">开始封禁</button><button class="btn ghost" id="no">取消</button></div>\`,s=>{$('#no').onclick=shut;$('#go').onclick=async()=>{const l=[...new Set(lines($('#bl').value))];if(!l.length)return toast('请先填写列表','bad');if(!await danger({t:'封禁 '+l.length+' 个玩家？',m:'此操作会立即生效。',ok:'确认封禁'},()=>P.bn._reopen&&0))return;let ok=0,bad=[];$('#go').disabled=true;for(let i=0;i<l.length;i++){try{await api('ban',{userId:l[i],reason:$('#br').value||'banned',hours:+$('#bd').dataset.v});ok++}catch(x){bad.push(l[i])}$('#pg').style.width=((i+1)/l.length*100)+'%';$('#pt').textContent=\`\${i+1} / \${l.length}\`}toast(\`完成：成功 \${ok}，失败 \${bad.length}\`,bad.length?'warn':0);load()}});
 c._t=load;load()}};

/* ── 白名单 ── */
P.wl={t:'白名单',r(c){let D=[],q='',cf=null;
 c.innerHTML=\`<div class="card g"><div class="fl" style="border:0;padding:0"><div><b>仅白名单可用</b><div class="sub" id="wsub">开启后，未加入白名单的玩家无法启动脚本</div></div>\${sw('wr',false)}</div></div><div class="card g"><h2>添加玩家</h2><div class="bar" style="margin:0"><input class="in grow" id="wt" placeholder="游戏名或 UserId" autocomplete="off"><button class="btn" id="wa">加入</button></div><label class="lb">有效期</label>\${durChips('wd','0')}<div style="margin-top:12px"><button class="btn ghost sm" id="wb">批量添加…</button></div></div><div class="bar"><input class="in grow" id="q" placeholder="搜索白名单"><span class="sub" id="wc"></span></div><div class="card g" style="padding:8px 12px"><div id="ls">\${skel(4)}</div></div>\`;post(c);stagger(c);
 const rows=()=>{const qq=q.toLowerCase(),f=D.filter(x=>!qq||(x.u+x.i).toLowerCase().includes(qq)).sort((a,b)=>b.t-a.t);$('#wc').textContent=D.length+' 人';$('#ls').innerHTML=f.length?f.map(x=>{const pct=x.e?clamp((x.e-Date.now())/(x.e-x.t)*100,0,100):100;return\`<div class="row" data-u="\${esc(x.i)}">\${av(x.u)}<div class="grow"><b>\${esc(x.u)}</b><span>\${esc(x.i)} · \${x.e?'剩 '+left(x.e):'永久'}</span>\${x.e?\`<div class="meter" style="margin-top:6px;height:4px"><i style="width:\${pct}%;background:\${pct<20?'var(--warn)':'var(--ok)'}"></i></div>\`:''}</div><div class="end"><button class="btn sm ghost" data-rm="\${esc(x.i)}">移除</button></div></div>\`}).join(''):emptyBox('白名单是空的','在上方添加玩家')};
 const load=async()=>{try{const[d,f]=await Promise.all([api('wls'),api('cfg')]);D=d.list;cf=f;$('#wr').checked=!!f.wlRequired;rows()}catch(e){err(e)}};
 const add=async()=>{const t=$('#wt').value.trim();if(!t)return;try{await busy($('#wa'),api('wl',{userId:t,hours:+$('#wd').dataset.v}));$('#wt').value='';toast('已加入白名单');load()}catch(e){err(e)}};
 $('#wa').onclick=add;$('#wt').onkeydown=e=>{if(e.key==='Enter')add()};$('#q').oninput=e=>{q=e.target.value.trim();rows()};
 $('#wr').onchange=async e=>{const v=e.target.checked;if(v&&!D.length&&!await danger({t:'白名单还是空的',m:'现在开启后所有玩家（包括你自己）都无法启动脚本。仍要开启吗？',ok:'仍要开启',danger:1})){e.target.checked=false;return}try{await api('cfg',{wlRequired:v});toast(v?'已开启：仅白名单可用':'已关闭白名单限制')}catch(x){e.target.checked=!v;err(x)}};
 $('#ls').onclick=async e=>{const r=e.target.closest('[data-rm]'),u=e.target.closest('[data-u]');if(r){e.stopPropagation();if(!await danger({t:'移出白名单？',m:r.dataset.rm,ok:'移除'}))return;try{await api('unwl',{userId:r.dataset.rm});toast('已移除');load()}catch(x){err(x)}}else if(u)pSheet(u.dataset.u)};
 $('#wb').onclick=()=>sheet(\`<h2>批量添加白名单</h2><div class="sub">每行一个玩家名或 UserId。</div><textarea class="in mono" id="bl" style="min-height:150px;margin-top:10px"></textarea><label class="lb">有效期</label>\${durChips('bd','0')}<div class="meter" style="margin-top:16px"><i id="pg" style="background:var(--accent)"></i></div><div class="sub" id="pt" style="margin-top:6px"></div><div class="bar" style="margin:16px 0 0"><button class="btn" id="go">开始添加</button><button class="btn ghost" id="no">取消</button></div>\`,s=>{$('#no').onclick=shut;$('#go').onclick=async()=>{const l=[...new Set(lines($('#bl').value))];if(!l.length)return toast('请先填写列表','bad');$('#go').disabled=true;let ok=0;for(let i=0;i<l.length;i++){try{await api('wl',{userId:l[i],hours:+$('#bd').dataset.v});ok++}catch(x){}$('#pg').style.width=((i+1)/l.length*100)+'%';$('#pt').textContent=\`\${i+1} / \${l.length}\`}toast(\`完成：成功 \${ok} / \${l.length}\`);shut();load()}});
 c._t=load;load()}};

/* ── 设备 ── */
P.hw={t:'设备 / 多账号',r(c){let min=1,inf=null,all=[];
 c.innerHTML=\`<div class="bar"><input class="in grow" id="q" placeholder="筛选设备 ID">\${seg('mn',[['1','全部'],['2','≥ 2 个账号'],['3','≥ 3 个账号']],'1')}</div><div class="card g" style="padding:8px 12px"><div id="ls"></div></div>\`;post(c);stagger(c);
 const ls=$('#ls'),row=x=>\`<div class="row" data-h="\${esc(x.hwid)}"><div class="av" style="background:linear-gradient(135deg,\${x.n>2?'#ff453a,#ff9f0a':'#0a84ff,#5e5ce6'})">\${x.n}</div><div class="grow"><b class="mono">\${esc(x.hwid.slice(0,30))}…</b><span>\${x.n} 个账号 · \${ago(x.t)}</span></div><div class="end">\${x.n>2?'<span class="tag warn">可疑</span>':''}›</div></div>\`;
 const q=()=>$('#q').value.trim().toLowerCase(),vis=x=>x.n>=min&&(!q()||x.hwid.toLowerCase().includes(q()));
 const redraw=()=>{ls.innerHTML=all.filter(vis).map(row).join('')||emptyBox('没有符合条件的设备')};
 const start=()=>{if(inf)inf.stop();all=[];ls.innerHTML='';inf=infinite(ls,async cur=>{const d=await api('hwids'+(cur?'?cursor='+encodeURIComponent(cur):''));all.push(...d.list);ls.insertAdjacentHTML('beforeend',d.list.filter(vis).map(row).join(''));return{cursor:d.cursor,empty:!all.length}})};
 $('#mn').addEventListener('chg',e=>{min=+e.detail;redraw()});$('#q').oninput=redraw;ls.onclick=e=>{const r=e.target.closest('[data-h]');if(r)hwSheet(r.dataset.h)};c._x=()=>inf&&inf.stop();start()}};

/* ── 控制台 ── */
const FTPL=[['antiAfk','true','防挂机'],['fpsCap','60','FPS 上限'],['reportErrors','true','上报脚本错误'],['debug','false','调试输出']];
P.ct={t:'控制台',r(c){let f=null,pl='',orig='',dirty=false,fl={},places=[];
 c.innerHTML=\`<div class="card g">\${skel(3)}</div>\`;
 const mark=()=>{const d=JSON.stringify(collect())!==orig;if(d!==dirty){dirty=d;$('#sb').classList.toggle('on',d)}};
 const collect=()=>({announce:$('#an').value,minVer:$('#mv').value,poll:+$('#po').value,blockedPlaces:bp,flags:fl,webhook:$('#wh').value,susThreshold:+$('#sus').value,autoBanSus:$('#abs').checked});
 let bp=[];
 const flagRows=()=>{const e=Object.entries(fl);$('#fr').innerHTML=e.map(([k,v],i)=>\`<div class="kv"><input class="in mono" data-fk="\${i}" value="\${esc(k)}" placeholder="名称"><input class="in mono" data-fv="\${i}" value="\${esc(typeof v==='string'?JSON.stringify(v):String(v))}" placeholder="值"><button class="btn sm ghost" data-fd="\${i}">删除</button></div>\`).join('')||'<div class="sub" style="margin-bottom:8px">还没有开关。点下面的模板快速添加。</div>';$('#fj').value=JSON.stringify(fl,null,2)};
 const parseV=s=>{s=s.trim();if(s==='true')return true;if(s==='false')return false;if(s!==''&&!isNaN(+s))return +s;try{const v=JSON.parse(s);return v}catch(e){return s}};
 const chipsBp=()=>{$('#bpc').innerHTML=bp.map((x,i)=>\`<span class="chip x on">\${pname(x)}<b data-bi="\${i}">×</b></span>\`).join('')||'<span class="sub">没有禁用的游戏</span>'};
 const draw=()=>{const k=f.kill;c.innerHTML=\`<div class="card g"><h2>快捷操作</h2><div class="bar" style="margin:0"><button class="btn" id="bcb">广播通知</button><button class="btn ghost" id="exc">导出配置</button><button class="btn ghost" id="imc">导入配置</button><input type="file" id="imf" accept=".json" hidden></div></div>
 <div class="card g"><h2>全局开关</h2>\${flrow('紧急停用','立即断开所有客户端，并拒绝新的连接',sw('kill',f.kill,'rd'))}\${depBox('kd',\`<label class="lb">停用时玩家看到的消息</label><input class="in" id="km" value="\${esc(f.killMsg)}" maxlength="100"><div style="margin-top:10px"><button class="btn sm ghost" id="kms">保存消息</button></div>\`,f.kill)}\${flrow('仅白名单可用','未加入白名单的玩家无法启动',sw('wr',f.wlRequired))}</div>
 <div class="card g"><h2>公告与版本</h2><label class="lb">公告（玩家进入时弹出）</label><input class="in" id="an" value="\${esc(f.announce)}" maxlength="300"><label class="lb">最低脚本版本（低于此版本会被要求更新）</label><input class="in" id="mv" value="\${esc(f.minVer)}" placeholder="例如 5.0.0" maxlength="12"><label class="lb">心跳间隔 · 越小指令越快，请求越多</label>\${rng('po',5,120,1,f.poll,' 秒')}</div>
 <div class="card g"><h2>禁用游戏</h2><div class="chips" id="bpc"></div><div class="bar" style="margin:12px 0 0"><input class="in grow" id="bpi" inputmode="numeric" placeholder="输入 PlaceId，回车添加">\${places.length?\`<select class="in" id="bps" style="width:auto"><option value="">从已记录游戏选择</option>\${places.map(p=>\`<option value="\${esc(p[0])}">\${esc(p[1])}</option>\`).join('')}</select>\`:''}</div></div>
 <div class="card g"><h2>开关 Flags<span class="sp"></span>\${seg('fm',[['r','可视化'],['j','JSON']],'r')}</h2><div class="sub" style="margin-bottom:10px">脚本里用 <span class="mono">YT.flag("名称", 默认值)</span> 读取，修改后客户端会在下一次心跳自动同步。</div><div id="fv"><div id="fr"></div><div class="bar" style="margin:6px 0 0"><button class="btn ghost sm" id="fa">＋ 添加开关</button>\${FTPL.map(t=>\`<button class="chip" data-t="\${t[0]}">\${t[2]}</button>\`).join('')}</div></div><div id="fjw" hidden><textarea class="in mono" id="fj" style="min-height:180px"></textarea><div class="err" id="fje" style="text-align:left"></div></div></div>
 <div class="card g"><h2>多账号检测</h2><label class="lb">同一设备超过几个账号时标记为可疑</label>\${rng('sus',1,10,1,f.susThreshold,' 个')}\${flrow('自动封禁可疑设备','被标记的设备会立即封禁（可能误伤共用电脑的玩家）',sw('abs',f.autoBanSus,'rd'))}\${depBox('abw','<div class="banner warn" style="margin:6px 0 0"><b>自动封禁可能误伤：网吧、学校、家庭共用电脑都会触发。建议把阈值调到 4 以上。</b></div>',f.autoBanSus)}</div>
 <div class="card g"><h2>Discord Webhook</h2><div class="sub" style="margin-bottom:8px">新玩家、封禁玩家启动、多账号设备会推送到这里</div><input class="in" id="wh" value="\${esc(f.webhook)}" placeholder="https://discord.com/api/webhooks/..."></div>
 <div class="card g"><h2>白名单专属代码<span class="sp"></span><span class="sub" id="plc"></span></h2><div class="sub" style="margin-bottom:10px">只有白名单玩家能从服务器取到这段 Lua，不会出现在公开脚本里。</div><textarea class="in mono" id="pl" spellcheck="false" style="min-height:200px;white-space:pre;overflow:auto">\${esc(pl)}</textarea><div style="margin-top:12px"><button class="btn" id="sp">保存代码</button></div></div>
 <div class="savebar g" id="sb"><span><b>有未保存的更改</b></span><span style="display:flex;gap:8px"><button class="btn ghost sm" id="rv">还原</button><button class="btn sm" id="sv">保存配置</button></span></div>\`;
  post(c);stagger(c);fl={...f.flags};bp=[...f.blockedPlaces];flagRows();chipsBp();orig=JSON.stringify(collect());dirty=false;
  const plc=()=>{$('#plc').textContent=$('#pl').value.length.toLocaleString()+' 字符'};plc();$('#pl').oninput=plc;
  $('#kill').onchange=async e=>{const v=e.target.checked;if(v&&!await danger({t:'开启紧急停用？',m:'所有在线玩家会立刻被断开，直到你关闭它。',ok:'开启停用'})){e.target.checked=false;return}try{await api('cfg',{kill:v});f.kill=v;$('#kd').classList.toggle('off',!v);toast(v?'已紧急停用':'已恢复服务',v?'warn':0)}catch(x){e.target.checked=!v;err(x)}};
  $('#kms').onclick=()=>api('cfg',{killMsg:$('#km').value}).then(()=>{f.killMsg=$('#km').value;toast('已保存')}).catch(err);
  $('#wr').onchange=async e=>{try{await api('cfg',{wlRequired:e.target.checked});f.wlRequired=e.target.checked;toast(e.target.checked?'已开启：仅白名单可用':'已关闭白名单限制')}catch(x){e.target.checked=!e.target.checked;err(x)}};
  $('#abs').onchange=e=>{$('#abw').classList.toggle('off',!e.target.checked);if(e.target.checked&&+$('#sus').value<4){$('#sus').value=4;rgFill($('#sus'))}mark()};
  ['an','mv','po','wh','sus'].forEach(i=>$('#'+i).addEventListener('input',mark));
  $('#bpi').onkeydown=e=>{if(e.key==='Enter'){const v=e.target.value.replace(/\\D/g,'');if(v&&!bp.includes(v)){bp.push(v);e.target.value='';chipsBp();mark()}}};if($('#bps'))$('#bps').onchange=e=>{const v=e.target.value;if(v&&!bp.includes(v)){bp.push(v);chipsBp();mark()}e.target.value=''};
  $('#bpc').onclick=e=>{const b=e.target.closest('[data-bi]');if(b){bp.splice(+b.dataset.bi,1);chipsBp();mark()}};
  $('#fm').addEventListener('chg',e=>{if(e.detail==='j'){$('#fv').hidden=true;$('#fjw').hidden=false;$('#fj').value=JSON.stringify(fl,null,2)}else{try{fl=JSON.parse($('#fj').value||'{}');$('#fje').textContent=''}catch(x){$('#fje').textContent='JSON 格式不正确，已保留原有开关';$('#fm').dataset.v='j';return}$('#fv').hidden=false;$('#fjw').hidden=true;flagRows();mark()}});
  $('#fj').oninput=()=>{try{fl=JSON.parse($('#fj').value||'{}');$('#fje').textContent='';mark()}catch(x){$('#fje').textContent='JSON 格式不正确'}};
  $('#fr').addEventListener('change',e=>{const k=e.target.dataset.fk,v=e.target.dataset.fv;const ent=Object.entries(fl);if(k!=null){const[o,val]=ent[+k];if(!e.target.value.trim()||!/^\\w{1,32}$/.test(e.target.value.trim())){toast('名称只能用字母、数字、下划线','bad');e.target.value=o;return}delete fl[o];fl[e.target.value.trim()]=val}else if(v!=null){fl[ent[+v][0]]=parseV(e.target.value)}flagRows();mark()});
  $('#fr').onclick=e=>{const d=e.target.closest('[data-fd]');if(d){delete fl[Object.keys(fl)[+d.dataset.fd]];flagRows();mark()}};
  $('#fa').onclick=()=>{let n='flag'+(Object.keys(fl).length+1);fl[n]=true;flagRows();mark()};
  c.querySelector('#fv').addEventListener('click',e=>{const t=e.target.closest('[data-t]');if(t){const T=FTPL.find(x=>x[0]===t.dataset.t);fl[T[0]]=parseV(T[1]);flagRows();mark()}});
  $('#sv').onclick=async()=>{if($('#fm').dataset.v==='j'){try{fl=JSON.parse($('#fj').value||'{}')}catch(x){return toast('Flags 不是有效的 JSON','bad')}}try{await busy($('#sv'),api('cfg',collect()));Object.assign(f,collect());orig=JSON.stringify(collect());dirty=false;$('#sb').classList.remove('on');toast('配置已保存')}catch(x){err(x)}};
  $('#rv').onclick=()=>{draw()};$('#sp').onclick=()=>busy($('#sp'),api('payload',{src:$('#pl').value})).then(()=>toast('代码已保存')).catch(err);
  $('#bcb').onclick=bcSheet;$('#exc').onclick=()=>dl('yutong-config.json',JSON.stringify({cfg:f,payload:$('#pl').value},null,2));
  $('#imc').onclick=()=>$('#imf').click();$('#imf').onchange=function(){const fi=this.files[0];if(!fi)return;fi.text().then(t=>{const j=JSON.parse(t),cf=j.cfg||{};return api('cfg',{kill:false,wlRequired:cf.wlRequired,killMsg:cf.killMsg,announce:cf.announce,minVer:cf.minVer,poll:cf.poll,blockedPlaces:cf.blockedPlaces||[],flags:cf.flags||{},webhook:cf.webhook,susThreshold:cf.susThreshold,autoBanSus:cf.autoBanSus}).then(()=>j.payload!=null?api('payload',{src:j.payload}):0)}).then(()=>{toast('配置已导入（紧急停用已保持关闭）');load()}).catch(()=>toast('导入失败，请确认文件正确','bad'))}};
 const load=async()=>{try{const[a,b,s]=await Promise.all([api('cfg'),api('payload'),api('stats').catch(()=>({pn:{}}))]);f=a;pl=b.src;PN={...PN,...(s.pn||{})};places=Object.entries(PN).map(x=>[x[0],x[1]]);draw()}catch(e){err(e)}};
 c._x=()=>{$('#bulk').classList.remove('on')};load()}};
function bcSheet(){const ps=Object.entries(PN);sheet(\`<h2>广播给所有在线玩家</h2>\${seg('bt',[['notify','通知（短）'],['msg','消息（长）']],'notify')}<label class="lb">内容</label><textarea class="in" id="bm" maxlength="200" placeholder="最多 200 字"></textarea><div class="sub" style="text-align:right"><span id="bn">0</span>/200</div><label class="lb">范围</label><select class="in" id="bpid"><option value="">所有游戏</option>\${ps.map(p=>\`<option value="\${esc(p[0])}">\${esc(p[1])}</option>\`).join('')}</select><div class="bar" style="margin:18px 0 0"><button class="btn" id="go">发送</button><button class="btn ghost" id="no">取消</button></div>\`,s=>{$('#bm').oninput=e=>$('#bn').textContent=e.target.value.length;$('#no').onclick=shut;$('#go').onclick=async()=>{const m=$('#bm').value.trim();if(!m)return toast('请输入内容','bad');try{await busy($('#go'),api('bc',{c:$('#bt').dataset.v,m,pl:$('#bpid').value}));toast('已广播，在线玩家将在下一次心跳收到');shut()}catch(e){err(e)}}})}

/* ── 安全中心 ── */
const SEV={login_ok:['登录成功','var(--ok)'],login_fail:['登录失败','var(--bad)'],login_locked:['登录被锁定','var(--bad)'],honeypot:['扫描器触发蜜罐','var(--warn)'],bot_api:['拦截爬虫(API)','var(--warn)'],bot_page:['拦截爬虫(页面)','var(--warn)'],ip_denied:['IP 白名单拦截','var(--warn)'],setup:['创建管理员','var(--accent)'],setup_badcode:['安装码错误','var(--bad)'],pw_change:['修改账号信息','var(--accent)'],pw_wrong:['改密时当前密码错误','var(--bad)']};
P.sc={t:'安全中心',r(c){let ips=[],cfg=null;
 c.innerHTML=\`<div class="card g">\${skel(3)}</div>\`;
 const draw=(me,ss,lg)=>{const chk=[['已设置脚本密钥 SCRIPT_KEY',me.key,'在 Worker 变量里添加并同步到 roblox.lua'],['已设置安装码 SETUP_CODE',me.setup,'防止别人抢先创建账号（账号已创建后影响不大）'],['已启用 Cloudflare Turnstile',me.ts,'可选，为登录增加一层真人验证'],['已开启两步验证',me.otp,'强烈建议'],['已限制后台 IP',(cfg.adminIps||[]).length>0,'仅适合固定 IP，可选']],sc=chk.filter(x=>x[1]).length;
  c.innerHTML=\`<div class="g2"><div class="card g"><h2>安全评分<span class="sp"></span><span class="tag \${sc>=4?'ok':sc>=2?'warn':'bad'}">\${sc} / \${chk.length}</span></h2><div class="meter" style="margin-bottom:12px"><i style="width:\${sc/chk.length*100}%;background:\${sc>=4?'var(--ok)':sc>=2?'var(--warn)':'var(--bad)'}"></i></div>\${chk.map(x=>\`<div class="chk \${x[1]?'ok':''}" style="align-items:flex-start;padding:5px 0"><i>✓</i><div><div style="color:var(--fg)">\${x[0]}</div>\${x[1]?'':\`<div class="sub">\${x[2]}</div>\`}</div></div>\`).join('')}<div class="sub" style="margin-top:12px">你的当前连接：<span class="mono">\${esc(me.ip)}</span> \${flag(me.cc)}</div></div>
  <div class="card g"><h2>账号</h2><div class="kvs"><div><small>用户名</small><b>\${esc(me.u)}</b></div><div><small>两步验证</small><b>\${me.otp?'已开启':'未开启'}</b></div></div><label class="lb">当前密码（修改任何项都需要）</label><input class="in" id="o" type="password" autocomplete="current-password"><label class="lb">新用户名（不改就留空）</label><input class="in" id="nu" autocomplete="off" maxlength="24" placeholder="\${esc(me.u)}"><label class="lb">新密码（至少 8 位，不能是纯数字；不改就留空）</label><input class="in" id="np" type="password" autocomplete="new-password"><div class="meter" style="margin-top:8px"><i id="pm"></i></div><div class="err" id="pe" style="text-align:left"></div><div style="margin-top:12px"><button class="btn" id="cp">保存修改</button></div><div class="sub" style="margin-top:8px">保存后会退出其他所有设备。</div></div></div>
  <div class="g2"><div class="card g"><h2>两步验证（TOTP）</h2>\${me.otp?'<div class="sub" style="margin-bottom:12px">登录时需要认证器 App 里的 6 位动态码。</div><label class="lb">输入密码以关闭</label><input class="in" id="tp" type="password"><div style="margin-top:12px"><button class="btn red" id="toff">关闭两步验证</button></div>':'<div class="sub" style="margin-bottom:12px">用 Google Authenticator、1Password、Authy 等 App 添加，登录时多一道保险。</div><button class="btn" id="ton">开始设置</button><div id="tz"></div>'}</div>
  <div class="card g"><h2>后台 IP 白名单</h2><div class="sub" style="margin-bottom:10px">设置后，只有这些 IP 能访问后台，其他人看到的是 404。必须包含你当前的 IP。<b>如果 IP 经常变化请不要开启</b>；万一被锁在外面，到 Cloudflare 的 META KV 里删除 cfg 里的 adminIps 即可。</div><div class="chips" id="ic"></div><div class="bar" style="margin:12px 0 0"><input class="in grow" id="ii" placeholder="IP 地址，回车添加"><button class="btn ghost sm" id="im">添加我的 IP</button></div><div style="margin-top:12px"><button class="btn" id="is">保存白名单</button></div></div></div>
  <div class="card g"><h2>登录会话<span class="sp"></span><button class="btn ghost sm" id="so">退出其他设备</button></h2>\${ss.map(s=>\`<div class="row" style="cursor:default"><div class="av" style="background:var(--fill2)">\${s.cur?'●':'○'}</div><div class="grow"><b>\${esc(s.ua||'未知设备')}\${s.cur?' <span class="tag ok">当前</span>':''}</b><span>\${flag(s.cc)} \${esc(s.ip)} · 登录于 \${ago(s.t)}</span></div>\${s.cur?'':\`<button class="btn sm ghost" data-rv="\${esc(s.id)}">撤销</button>\`}</div>\`).join('')||emptyBox('没有会话')}</div>
  <div class="card g"><h2>安全日志<span class="sp"></span>\${seg('sf',[['','全部'],['fail','异常'],['ok','正常']],'')}</h2><div id="sl"></div></div>
  <div class="card g"><h2>当前防护</h2><div class="sub" style="line-height:1.9">• 登录前强制真人验证（按住 + 工作量证明\${me.ts?' + Turnstile':''}）<br>• 密码 PBKDF2 加盐哈希，5 次错误锁定 15 分钟<br>• 会话 Cookie：HttpOnly · Secure · SameSite=Strict · 绑定浏览器指纹，可随时撤销<br>• 严格 CSP（脚本 nonce）、禁止被嵌入、禁止索引与缓存<br>• 爬虫 / 扫描器 User-Agent 拦截，敏感路径蜜罐自动封锁 IP 1 小时<br>• 所有写操作需要 CSRF 头 + 同源校验<br>• 脚本端：密钥校验 + 时间戳校验 + 内存限流 + 请求体大小限制</div></div>\`;
  post(c);stagger(c);
  const pm=()=>{const s=pwScore($('#np').value),m=$('#pm');m.style.width=($('#np').value?s/5*100:0)+'%';m.style.background=s<=1?'var(--bad)':s<=3?'var(--warn)':'var(--ok)'};$('#np').oninput=pm;
  $('#cp').onclick=async()=>{const np=$('#np').value,nu=$('#nu').value.trim();if(!np&&!nu)return toast('没有要修改的内容','warn');if(np){const R=pwRules(np,nu||me.u).find(r=>!r[1]);if(R){$('#pe').textContent='新密码：'+R[0];return}}$('#pe').textContent='';try{await busy($('#cp'),api('pw',{old:$('#o').value,new:np,user:nu||undefined}));toast('已保存，其他设备已退出');load()}catch(e){$('#pe').textContent=(e&&e.msg)||'保存失败'}};
  const ton=$('#ton');if(ton)ton.onclick=async()=>{try{const d=await api('totp/new',{});$('#tz').innerHTML=\`<div class="kvs"><div style="grid-column:1/-1"><small>密钥（在认证器里选择“手动输入”）</small><b class="mono" id="ts" style="white-space:normal;word-break:break-all;cursor:pointer">\${d.secret}</b></div></div><div class="sub" style="word-break:break-all">或复制链接导入：<a href="#" id="tu">复制 otpauth 链接</a></div><label class="lb">输入认证器显示的 6 位验证码</label><div class="bar" style="margin:0"><input class="in grow" id="tc" inputmode="numeric" maxlength="6" placeholder="000000"><button class="btn" id="te">验证并开启</button></div>\`;$('#ts').onclick=()=>copy(d.secret);$('#tu').onclick=e=>{e.preventDefault();copy(d.uri)};$('#te').onclick=async()=>{try{await api('totp/on',{code:$('#tc').value});toast('两步验证已开启');load()}catch(x){err(x)}};ton.hidden=true}catch(e){err(e)}};
  const toff=$('#toff');if(toff)toff.onclick=async()=>{try{await api('totp/off',{p:$('#tp').value});toast('已关闭两步验证');load()}catch(e){err(e)}};
  ips=[...(cfg.adminIps||[])];const dI=()=>{$('#ic').innerHTML=ips.map((x,i)=>\`<span class="chip x on">\${esc(x)}<b data-i="\${i}">×</b></span>\`).join('')||'<span class="sub">未限制（任何 IP 都能访问登录页）</span>'};dI();$('#ic').onclick=e=>{const b=e.target.closest('[data-i]');if(b){ips.splice(+b.dataset.i,1);dI()}};
  const addIp=v=>{v=v.trim();if(v&&!ips.includes(v)){ips.push(v);dI()}};$('#ii').onkeydown=e=>{if(e.key==='Enter'){addIp(e.target.value);e.target.value=''}};$('#im').onclick=()=>addIp(me.ip);
  $('#is').onclick=async()=>{if(ips.length&&!await danger({t:'启用 IP 白名单？',m:'只有 '+ips.join('、')+' 能访问后台。如果之后 IP 变化，你需要去 Cloudflare 的 META KV 手动清除。',ok:'启用',danger:1}))return;try{await api('secset',{adminIps:ips});cfg.adminIps=ips;toast('已保存')}catch(e){err(e)}};
  $('#so').onclick=async()=>{try{await api('sess/others',{});toast('已退出其他设备');load()}catch(e){err(e)}};$$('[data-rv]',c).forEach(b=>b.onclick=async()=>{try{await api('sess/revoke',{id:b.dataset.rv});toast('已撤销');load()}catch(e){err(e)}});
  const bad=['login_fail','login_locked','honeypot','bot_api','bot_page','ip_denied','setup_badcode','pw_wrong'],sl=()=>{const f=$('#sf').dataset.v,a=lg.filter(x=>!f||(f==='fail'?bad.includes(x.e):!bad.includes(x.e)));$('#sl').innerHTML=a.length?a.slice(0,60).map(x=>{const s=SEV[x.e]||[x.e,'var(--fg3)'];return\`<div class="tl-i"><i style="background:\${s[1]}"></i><div style="min-width:0"><b style="font-weight:600">\${s[0]}</b><div class="sub" style="word-break:break-all">\${flag(x.cc)} \${esc(x.ip)}\${x.x?' · '+esc(x.x):''}<br>\${esc(x.ua)}</div></div><span class="t">\${ago(x.t)}</span></div>\`}).join(''):emptyBox('没有记录')};sl();$('#sf').addEventListener('chg',sl)};
 const load=async()=>{try{const[me,s,l,f]=await Promise.all([api('me'),api('sessions'),api('seclog'),api('cfg')]);ME=me;cfg=f;draw(me,s.list,l.list)}catch(e){err(e)}};load()}};

/* ── 外观设置（声明式，支持依赖联动） ── */
const SCH=[
 {g:'背景',items:[
  {k:'bgpick'},
  {k:'bgBlur',t:'r',l:'壁纸模糊',mn:0,mx:40,u:'px'},{k:'dim',t:'r',l:'壁纸压暗 / 提亮遮罩',mn:0,mx:80,u:'%'},{k:'bgSat',t:'r',l:'壁纸饱和度',mn:0,mx:220,u:'%'},{k:'bgBr',t:'r',l:'壁纸亮度',mn:40,mx:150,u:'%'},
  {k:'par',t:'s',l:'视差跟随',s:'壁纸随鼠标轻微移动',need:'anim'},
  {k:'aur',t:'s',l:'极光动态背景',s:'彩色光斑缓慢漂移，略增加显卡负担',need:'anim'},{k:'aurS',t:'r',l:'极光速度（数值越大越慢）',mn:8,mx:60,u:'s',show:'aur'},
  {k:'ptc',t:'s',l:'粒子连线',s:'光点随鼠标散开',need:'anim'},{k:'ptcN',t:'r',l:'粒子数量',mn:20,mx:160,u:'',show:'ptc'},
  {k:'grain',t:'s',l:'胶片颗粒',s:'叠加细腻噪点，让玻璃更有质感'}]},
 {g:'玻璃材质',items:[
  {k:'glass',t:'s',l:'毛玻璃模糊',s:'关闭可显著提升低端设备的流畅度'},{k:'gb',t:'r',l:'模糊强度',mn:0,mx:80,u:'px',show:'glass'},{k:'gs',t:'r',l:'色彩增强',mn:100,mx:260,u:'%',show:'glass'},
  {k:'ga',t:'r',l:'玻璃不透明度',mn:2,mx:60,u:'%'},{k:'gba',t:'r',l:'边缘描边',mn:0,mx:60,u:'%'},{k:'spec',t:'r',l:'顶部高光',mn:0,mx:90,u:'%'},{k:'sh',t:'r',l:'阴影深度',mn:0,mx:70,u:'%'},{k:'r',t:'r',l:'圆角大小',mn:4,mx:40,u:'px'}]},
 {g:'颜色',items:[{k:'mode',t:'g',l:'明暗模式',o:[['dark','深色'],['light','浅色'],['auto','跟随系统']]},{k:'colors'}]},
 {g:'字体',items:[{k:'font',t:'g',l:'字体风格',o:Object.entries(FONTS).map(x=>[x[0],x[1][0]])},{k:'fontCustom',t:'x',l:'自定义字体名（需设备已安装）',show:'font=custom',ph:'例如 LXGW WenKai'},{k:'fs',t:'r',l:'基础字号',mn:12,mx:20,u:'px'},{k:'ls',t:'r',l:'字间距',mn:-1,mx:3,st:.1,u:'px'}]},
 {g:'布局',items:[{k:'nav',t:'g',l:'导航位置',o:[['side','左侧栏'],['dock','底部悬浮坞'],['top','顶部标签']]},{k:'dens',t:'g',l:'信息密度',o:[['compact','紧凑'],['cozy','标准'],['roomy','宽松']]},{k:'gap',t:'r',l:'间距缩放',mn:60,mx:160,u:'%',cv:1},{k:'maxw',t:'r',l:'内容最大宽度',mn:760,mx:1800,st:20,u:'px'}]},
 {g:'动画与交互',items:[
  {k:'anim',t:'s',l:'启用动画',s:'总开关，关闭后下方动画选项会变灰'},{k:'spd',t:'r',l:'动画速度',mn:40,mx:250,u:'%',dim:'anim'},{k:'pt',t:'g',l:'页面切换效果',o:[['slide','上浮'],['fade','淡入'],['zoom','缩放']],dim:'anim'},
  {k:'cnt',t:'s',l:'数字滚动',dim:'anim'},{k:'tilt',t:'s',l:'卡片 3D 倾斜',s:'鼠标悬停时跟随倾斜',dim:'anim'},{k:'rip',t:'s',l:'按钮水波纹',dim:'anim'},{k:'hap',t:'s',l:'触感反馈',s:'手机上点击开关时轻微震动'}]},
 {g:'行为',items:[{k:'ref',t:'g',l:'自动刷新',o:[[0,'关闭'],[5,'5 秒'],[10,'10 秒'],[30,'30 秒']]},{k:'toast',t:'g',l:'提示位置',o:[['top','顶部'],['bottom','底部']]},{k:'cfm',t:'s',l:'危险操作二次确认',s:'封禁、踢出、停用等操作前弹出确认'}]}];
const SWC=['#0a84ff','#bf5af2','#ff375f','#30d158','#ff9f0a','#64d2ff','#ffd60a','#5e5ce6','#ff6482','#00f5a0'];
function lkVal(k){return k==='gap'?Math.round(LK.gap):LK[k]}
P.st={t:'外观与数据',r(c){
 const ctl=it=>{if(it.k==='bgpick')return\`<div class="bgs" id="bgs">\${PRE.map((g,i)=>\`<div data-p="p\${i}" class="\${LK.bg==='p'+i?'on':''}" style="background:\${g}" title="预设 \${i+1}"></div>\`).join('')}\${BGDATA?\`<div data-p="data" class="\${LK.bg==='data'?'on':''}" style="background-image:url('\${BGDATA}')" title="我的图片"></div>\`:''}</div><label class="lb">图片链接（https）</label><div class="bar" style="margin:0"><input class="in grow" id="bu" placeholder="https://" value="\${esc(LK.bgUrl)}"><button class="btn" id="ba">应用</button></div><div class="bar" style="margin:10px 0 0"><button class="btn ghost" id="bf">从相册 / 文件选择</button><button class="btn ghost" id="bx">从背景取色</button><input type="file" id="fi" accept="image/*" hidden></div><div class="sub" style="margin-top:6px">上传的图片会压缩后保存在本机，并可同步到云端，所有设备共用。</div>\`;
  if(it.k==='colors')return\`<label class="lb">主题色</label><div class="chips" id="sw1">\${SWC.map(x=>\`<button class="swatch \${LK.acc===x?'on':''}" data-c="\${x}" style="background:\${x}" aria-label="\${x}"></button>\`).join('')}<input type="color" id="cp1" value="\${LK.acc}" aria-label="自定义主题色"></div>\${flrow('渐变副色自动搭配','开启后副色会跟随主题色自动计算，关闭可手动选择',sw('aa',LK.accAuto))}\${depBox('c2w',\`<label class="lb">副色（用于渐变与图表）</label><div class="chips"><input type="color" id="cp2" value="\${LK.acc2}"></div>\`,!LK.accAuto)}\`;
  const v=lkVal(it.k),id='k_'+it.k;let h='';
  if(it.t==='r')h=\`<label class="lb">\${it.l}</label>\${rng(id,it.mn,it.mx,it.st||1,v,it.u)}\`;
  else if(it.t==='s')h=flrow(it.l,it.s||'',sw(id,!!v));
  else if(it.t==='g')h=\`<label class="lb">\${it.l}</label>\${seg(id,it.o,v)}\`;
  else if(it.t==='x')h=\`<label class="lb">\${it.l}</label><input class="in" id="\${id}" value="\${esc(v)}" placeholder="\${esc(it.ph||'')}">\`;
  return h};
 const visible=it=>{if(it.show){const[a,b]=it.show.split('=');return b?String(LK[a])===b:!!LK[a]}return true};
 const grp=g=>\`<div class="card g"><h2>\${g.g}</h2>\${g.items.map(it=>{const inner=ctl(it);if(it.show)return depBox('w_'+it.k,inner,visible(it));if(it.dim)return\`<div class="dep \${LK[it.dim]?'':'dim'}" id="w_\${it.k}" data-dim="\${it.dim}"><div>\${inner}</div></div>\`;return inner}).join('')}</div>\`;
 c.innerHTML=\`<div class="card g"><h2>风格预设</h2><div class="sub" style="margin-bottom:10px">一键切换整套外观，之后可以继续微调。</div><div class="chips" id="stl">\${Object.entries(STYLES).map(([k,v])=>\`<button class="chip" data-s="\${k}">\${v.n}</button>\`).join('')}</div><div class="bar" style="margin:14px 0 0"><button class="btn ghost sm" id="ex">导出主题</button><button class="btn ghost sm" id="im">导入主题</button><input type="file" id="imf" accept=".json" hidden><button class="btn ghost sm" id="up">同步到云端</button><button class="btn ghost sm" id="dn">从云端恢复</button><button class="btn ghost sm" id="rs">恢复默认</button></div></div>\${SCH.map(grp).join('')}
 <div class="card g"><h2>备份与恢复</h2><div class="sub" style="margin-bottom:12px">备份包含：控制台配置、白名单、封禁名单（玩家 / 设备 / IP）、专属代码和主题。</div><div class="bar" style="margin:0"><a class="btn" href="/api/backup" download>下载完整备份</a><button class="btn ghost" id="rb">从备份恢复</button><input type="file" id="rbf" accept=".json" hidden></div><div class="meter" style="margin-top:14px"><i id="rpg" style="background:var(--accent)"></i></div><div class="sub" id="rpt" style="margin-top:6px"></div></div>
 <div class="card g"><h2>数据维护</h2><div class="sub" style="margin-bottom:12px">删除没有玩家名或 UserId 的无效日志和白名单记录。</div><button class="btn" id="cu">清理无效数据</button></div>
 <div class="card g"><h2>操作记录</h2><div id="au" class="sub">加载中…</div></div>
 <div class="card g"><h2>清空日志</h2><div class="sub" style="margin-bottom:12px">所有执行日志将被永久删除，且无法恢复。</div><button class="btn red" id="cl">清空日志</button></div>
 <div class="card g"><h2>关于</h2><div class="sub">Yutong Panel v\${esc(ME.v||'')} · 账号 \${esc(ME.u||'')}</div></div>\`;
 post(c);stagger(c);
 const refreshDeps=()=>{SCH.forEach(g=>g.items.forEach(it=>{const w=$('#w_'+it.k,c);if(!w)return;if(it.show)w.classList.toggle('off',!visible(it));if(it.dim)w.classList.toggle('dim',!LK[it.dim])}))};
 const set=(o)=>{setLK(o);refreshDeps();liveInd()};
 SCH.forEach(g=>g.items.forEach(it=>{const el=$('#k_'+it.k,c);if(!el)return;
  if(it.t==='r')el.addEventListener('input',()=>{const v=+el.value;set(it.k==='gap'?{gap:v}:{[it.k]:v})});
  else if(it.t==='s')el.addEventListener('change',()=>{set({[it.k]:el.checked?1:0});if(it.k==='anim')toast(el.checked?'动画已开启':'动画已关闭，相关选项已变灰')});
  else if(it.t==='g')el.addEventListener('chg',e=>{const v=isNaN(+e.detail)||it.k==='mode'?e.detail:+e.detail;set({[it.k]:v});if(it.k==='nav')toast('导航已切换');if(it.k==='font')$$('.seg',c).forEach(segInd)});
  else if(it.t==='x')el.addEventListener('input',debounce(()=>set({[it.k]:el.value.trim()}),300))}));
 $('#bgs').onclick=e=>{const d=e.target.closest('[data-p]');if(!d)return;$$('#bgs div').forEach(x=>x.classList.toggle('on',x===d));set({bg:d.dataset.p})};
 $('#ba').onclick=()=>{const v=$('#bu').value.trim();if(!/^https:\\/\\//.test(v))return toast('请输入 https 开头的链接','bad');$$('#bgs div').forEach(x=>x.classList.remove('on'));set({bg:'url',bgUrl:v})};
 $('#bf').onclick=()=>$('#fi').click();$('#bx').onclick=bgAccent;
 $('#fi').onchange=function(){const f=this.files[0];if(!f)return;const im=new Image();im.onload=()=>{const k=Math.min(1,1920/Math.max(im.width,im.height)),cv=document.createElement('canvas');cv.width=im.width*k;cv.height=im.height*k;cv.getContext('2d').drawImage(im,0,0,cv.width,cv.height);let q=.82,d=cv.toDataURL('image/jpeg',q);while(d.length>1500000&&q>.3){q-=.1;d=cv.toDataURL('image/jpeg',q)}BGDATA=d;try{localStorage.setItem('yt_bgimg',d)}catch(e){toast('图片太大，浏览器无法保存','bad')}set({bg:'data'});api('look',{look:LK,bg:d},{quiet:1}).then(()=>toast('背景已应用并同步到云端')).catch(()=>toast('背景已应用（云端同步失败）','warn'));P.st.r(c)};im.src=URL.createObjectURL(f)};
 $('#sw1').onclick=e=>{const b=e.target.closest('[data-c]');if(!b)return;accSet(b.dataset.c)};$('#cp1').oninput=e=>accSet(e.target.value,1);
 function accSet(x,nu){const o={acc:x};if(LK.accAuto){const[h,s,l]=hex2hsl(x);o.acc2=hsl2hex((h+55)%360,Math.max(55,s),clamp(l,48,66));const i=$('#cp2');if(i)i.value=o.acc2}set(o);if(!nu)$$('#sw1 .swatch').forEach(s=>s.classList.toggle('on',s.dataset.c===x))}
 $('#aa').onchange=e=>{LK.accAuto=e.target.checked?1:0;$('#c2w').classList.toggle('off',!!LK.accAuto);if(LK.accAuto)accSet(LK.acc,1);else applyLook()};$('#cp2').oninput=e=>set({acc2:e.target.value});
 $('#stl').onclick=e=>{const b=e.target.closest('[data-s]');if(b){applyStyle(b.dataset.s);P.st.r(c)}};
 $('#ex').onclick=()=>dl('yutong-theme.json',JSON.stringify(LK,null,2));$('#im').onclick=()=>$('#imf').click();$('#imf').onchange=function(){const f=this.files[0];if(f)f.text().then(t=>{setLK({...LD,...JSON.parse(t)});toast('主题已导入');P.st.r(c)}).catch(()=>toast('文件无法识别','bad'))};
 $('#rs').onclick=()=>{setLK({...LD});toast('已恢复默认外观');P.st.r(c)};
 $('#up').onclick=()=>api('look',{look:LK,...(LK.bg==='data'&&BGDATA?{bg:BGDATA}:{})}).then(()=>toast('已同步到云端')).catch(err);
 $('#dn').onclick=async()=>{try{const d=await api('look');if(!d.look)return toast('云端还没有保存过外观','warn');if(d.bg){BGDATA=d.bg;try{localStorage.setItem('yt_bgimg',d.bg)}catch(e){}}setLK({...LD,...d.look},false);toast('已从云端恢复');P.st.r(c)}catch(e){err(e)}};
 $('#rb').onclick=()=>$('#rbf').click();$('#rbf').onchange=async function(){const f=this.files[0];if(!f)return;let d;try{d=JSON.parse(await f.text());if(d.app!=='yutong')throw 0}catch(e){return toast('这不是有效的备份文件','bad')}if(!await danger({t:'从备份恢复？',m:'会覆盖当前的控制台配置，并合并白名单与封禁名单。',ok:'开始恢复'}))return;const jobs=[{cfg:d.cfg,payload:d.payload}];const ch=(k,a)=>{for(let i=0;i<(a||[]).length;i+=80)jobs.push({[k]:a.slice(i,i+80)})};ch('wl',d.wl);ch('ban',d.ban);ch('hb',d.hb);ch('ib',d.ib);try{for(let i=0;i<jobs.length;i++){await api('restore',{data:jobs[i]});$('#rpg').style.width=((i+1)/jobs.length*100)+'%';$('#rpt').textContent=\`\${i+1} / \${jobs.length}\`}if(d.look){setLK({...LD,...d.look},false)}toast('备份已恢复')}catch(e){err(e)}};
 $('#cu').onclick=()=>{const b=$('#cu');b.disabled=true;let n=0;const run=(t,cu)=>api('cleanup',{t,cursor:cu||''}).then(d=>{n+=d.removed||0;if(d.again)run(t,cu);else if(d.cursor)run(t,d.cursor);else if(t==='logs')run('wl','');else{b.disabled=false;toast('已清理 '+n+' 条无效数据')}}).catch(e=>{b.disabled=false;err(e)});run('logs','')};
 api('audit').then(d=>{$('#au').innerHTML=d.list.length?d.list.slice(0,40).map(x=>\`<div class="tl-i"><i></i><div>\${esc(x.a)}</div><span class="t">\${ago(x.t)}</span></div>\`).join(''):'暂无记录'}).catch(()=>{});
 $('#cl').onclick=()=>ask({t:'清空所有日志？',m:'此操作无法撤销。',typed:'CONFIRM',danger:1,ok:'清空'}).then(ok=>{if(!ok)return;(function step(){api('clear',{}).then(d=>{if(d.left)step();else toast('日志已清空')}).catch(err)})()})}};
function applyStyle(k){const s=STYLES[k];if(!s)return;const base={...LD,...(s.v.mode?{}:{mode:LK.mode}),nav:LK.nav,font:LK.font,fontCustom:LK.fontCustom,anim:LK.anim,spd:LK.spd,ref:LK.ref,cfm:LK.cfm,bgUrl:LK.bgUrl,toast:LK.toast};const o={...base,...s.v};if(s.v.acc)o.accAuto=0;setLK(o);toast('已切换：'+s.n)}

/* ── 启动 ── */
document.title='Yutong';
applyLook(false);
showAuth();
})();
</script></body></html>
`;

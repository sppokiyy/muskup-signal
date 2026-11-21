import { DurableObject } from 'cloudflare:workers';

// Сервер бачить лише метадані: ID, публічні ключі, шифротекст. Паролів і SDP/ICE у відкритому вигляді тут немає.
// Дозволені поля кожного типу повідомлення (все інше відкидається, а не пересилається)
const SCHEMA = {
  'connect-request':   { v: 'num', epk: 'b64:100', n: 'b64:40' },
  'connect-challenge': { epk: 'b64:100', n: 'b64:40' },
  'connect-auth':      { proof: 'b64:64' },
  'connect-auth-ok':   { proof: 'b64:64' },
  'connect-response':  { ok: 'bool', reason: 'str:20' },
  'offer':             { d: 'b64:24000' },
  'answer':            { d: 'b64:24000' },
  'ice':               { d: 'b64:4000' },
  'hangup':            {}
};
const B64 = /^[A-Za-z0-9+/=_-]*$/;
const MAX_MSG = 32768;
const LIMITS = { all: [120, 10000], req: [6, 60000] }; // [кількість, вікно мс]

function send(ws, obj) { try { ws.send(JSON.stringify(obj)); } catch (_) {} }
function clean(m) {
  const sch = SCHEMA[m.type]; if (!sch) return null;
  const out = { type: m.type };
  for (const [k, t] of Object.entries(sch)) {
    const v = m[k]; if (v === undefined) return null;
    if (t === 'num') { if (typeof v !== 'number' || v < 0 || v > 100) return null; }
    else if (t === 'bool') { if (typeof v !== 'boolean') return null; }
    else {
      const [kind, max] = t.split(':');
      if (typeof v !== 'string' || v.length > Number(max)) return null;
      if (kind === 'b64' && !B64.test(v)) return null;
    }
    out[k] = v;
  }
  return out;
}
async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function hit(map, key, [n, win]) { // true, якщо ліміт перевищено
  const now = Date.now(); const a = (map.get(key) || []).filter((t) => now - t < win);
  a.push(now); map.set(key, a);
  if (map.size > 5000) for (const [k, v] of map) if (!v.length || now - v[v.length - 1] > win) map.delete(k);
  return a.length > n;
}

export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.rate = new Map(); this.regIp = new Map();
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  async fetch(request) {
    const ip = request.headers.get('CF-Connecting-IP') || '';
    if (this.ctx.getWebSockets().length > 4000) return new Response('busy', { status: 503 });
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ ip });
    return new Response(null, { status: 101, webSocket: client });
  }

  find(id) {
    for (const ws of this.ctx.getWebSockets()) {
      const a = ws.deserializeAttachment();
      if (a && a.id === id) return ws;
    }
    return null;
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== 'string' || message.length > MAX_MSG) return;
    const me = ws.deserializeAttachment() || {};
    const sid = String(me.ip || '') + '|' + (me.id || '');
    if (hit(this.rate, 'a|' + sid, LIMITS.all)) { try { ws.close(1008, 'rate'); } catch (_) {} return; }
    let m;
    try { m = JSON.parse(message); } catch (_) { return; }
    if (!m || typeof m !== 'object') return;

    if (m.type === 'register') {
      const id = String(m.id), tok = String(m.tok || '');
      if (!/^\d{9}$/.test(id) || !/^[0-9a-f]{64}$/.test(tok)) return send(ws, { type: 'error', code: 'bad-id' });
      if (me.id && me.id !== id) return; // один сокет — один ID
      const h = await sha256hex(tok);
      const key = 'id:' + id;
      const stored = await this.ctx.storage.get(key);
      if (!stored) {
        if (hit(this.regIp, String(me.ip), [10, 3600000])) return send(ws, { type: 'error', code: 'rate' });
        await this.ctx.storage.put(key, h); // перший, хто зайняв ID, стає його власником
      } else if (stored !== h) return send(ws, { type: 'id-conflict' });
      const old = this.find(id);
      if (old && old !== ws) { try { old.close(4000, 'replaced'); } catch (_) {} } // той самий власник, нова сесія
      ws.serializeAttachment({ ip: me.ip, id });
      return send(ws, { type: 'registered', id });
    }

    if (!me.id || typeof m.to !== 'string' || !/^\d{9}$/.test(m.to)) return;
    const out = clean(m); if (!out) return;
    if (out.type === 'connect-request' && (hit(this.rate, 'r|' + me.id, LIMITS.req) || hit(this.rate, 't|' + m.to, [20, 60000]))) return send(ws, { type: 'connect-response', from: m.to, ok: false, reason: 'locked' });
    const target = this.find(m.to);
    if (!target) return send(ws, { type: 'peer-offline', to: m.to });
    out.from = me.id; // відправника визначає сервер
    send(target, out);
  }

  async webSocketClose(ws, code) {
    try { ws.close(code && code !== 1005 && code !== 1006 ? code : 1000); } catch (_) {}
  }
  async webSocketError() {}
}

export default {
  async fetch(request, env) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('MUSKUP signaling OK', { headers: { 'content-type': 'text/plain; charset=utf-8', 'x-content-type-options': 'nosniff' } });
    }
    return env.HUB.get(env.HUB.idFromName('main')).fetch(request);
  }
};

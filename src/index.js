import { DurableObject } from 'cloudflare:workers';

const ALLOWED = new Set(['connect-request', 'connect-response', 'offer', 'answer', 'ice', 'hangup']);

function send(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch (_) {}
}

export class Hub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  async fetch() {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
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
    if (typeof message !== 'string' || message.length > 65536) return;
    let m;
    try { m = JSON.parse(message); } catch (_) { return; }
    const me = ws.deserializeAttachment();

    if (m.type === 'register') {
      const id = String(m.id);
      if (!/^\d{9}$/.test(id)) return send(ws, { type: 'error', code: 'bad-id' });
      if (me && me.id === id) return send(ws, { type: 'registered', id });
      if (this.find(id)) return send(ws, { type: 'id-taken' });
      ws.serializeAttachment({ id });
      return send(ws, { type: 'registered', id });
    }

    if (!me || !me.id || !ALLOWED.has(m.type) || !m.to) return;
    const target = this.find(String(m.to));
    if (!target) return send(ws, { type: 'peer-offline', to: m.to });
    m.from = me.id;
    send(target, m);
  }

  async webSocketClose(ws, code) {
    try { ws.close(code && code !== 1005 && code !== 1006 ? code : 1000); } catch (_) {}
  }
  async webSocketError() {}
}

export default {
  async fetch(request, env) {
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('MUSKUP signaling OK', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    return env.HUB.get(env.HUB.idFromName('main')).fetch(request);
  }
};

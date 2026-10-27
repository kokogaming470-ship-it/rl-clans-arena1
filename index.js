const { Redis } = require("@upstash/redis");
const crypto = require("crypto");
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN,
});
const cfg = { ...process.env, ...Object.fromEntries(Object.entries(require("../discord-config.js")).filter(([, v]) => v)) };
const { DISCORD_CLIENT_ID: CID, DISCORD_CLIENT_SECRET: SEC, SESSION_SECRET: KEY, SITE_URL } = cfg;
const ADMINS = (cfg.ADMIN_IDS || "").split(",").map(s => s.trim()).filter(Boolean);
const COLS = ["rules", "schedule", "applications", "visitors", "logs"];
const sign = v => crypto.createHmac("sha256", KEY).update(v).digest("base64url");
const mk = o => { const b = Buffer.from(JSON.stringify(o)).toString("base64url"); return b + "." + sign(b); };
function sess(req) {
  const m = (req.headers.cookie || "").match(/rl=([^;]+)/); if (!m) return null;
  const [b, s] = m[1].split("."); if (!b || s !== sign(b)) return null;
  try { return JSON.parse(Buffer.from(b, "base64url").toString()); } catch { return null; }
}
const json = (res, c, o) => { res.statusCode = c; res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(o)); };
const hash = async c => { const h = (await redis.hgetall(c)) || {}; return Object.entries(h).map(([id, v]) => ({ id, ...(typeof v === "string" ? JSON.parse(v) : v) })); };

module.exports = async (req, res) => {
  const u = new URL(req.url, "http://x"), p = u.pathname.replace(/\/$/, "");
  const me = sess(req), adm = !!me && ADMINS.includes(me.id);
  try {
    if (p === "/api/login") {
      const q = new URLSearchParams({ client_id: CID, redirect_uri: SITE_URL + "/api/callback", response_type: "code", scope: "identify" });
      res.statusCode = 302; res.setHeader("Location", "https://discord.com/oauth2/authorize?" + q); return res.end();
    }
    if (p === "/api/callback") {
      const t = await (await fetch("https://discord.com/api/oauth2/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: CID, client_secret: SEC, grant_type: "authorization_code", code: u.searchParams.get("code") || "", redirect_uri: SITE_URL + "/api/callback" }) })).json();
      const d = await (await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + t.access_token } })).json();
      if (!d.id) { res.statusCode = 302; res.setHeader("Location", "/"); return res.end(); }
      res.setHeader("Set-Cookie", `rl=${mk({ id: d.id, name: d.global_name || d.username })}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`);
      res.statusCode = 302; res.setHeader("Location", "/"); return res.end();
    }
    if (p === "/api/logout") { res.setHeader("Set-Cookie", "rl=; Path=/; Max-Age=0"); res.statusCode = 302; res.setHeader("Location", "/"); return res.end(); }
    if (p === "/api/me") return json(res, 200, me ? { id: me.id, name: me.name, isAdmin: adm } : null);

    if (p === "/api/db" && req.method === "GET") {
      const c = u.searchParams.get("c"); if (!COLS.includes(c)) return json(res, 400, {});
      let l = await hash(c);
      if (c === "rules" || c === "schedule") return json(res, 200, l);
      if (!me) return json(res, 401, []);
      if (!adm) l = l.filter(x => x.id === me.id && (c === "applications" || c === "visitors"));
      return json(res, 200, l);
    }
    if (p === "/api/db" && req.method === "POST") {
      if (!me) return json(res, 401, {});
      let b = req.body; if (typeof b === "string") b = JSON.parse(b);
      const { c, id, op, data } = b; if (!COLS.includes(c) || !id) return json(res, 400, {});
      const cur = await redis.hget(c, id); const old = cur ? (typeof cur === "string" ? JSON.parse(cur) : cur) : null;
      const put = o => redis.hset(c, { [id]: JSON.stringify(o) });
      if (adm) {
        if (op === "delete") await redis.hdel(c, id);
        else await put(op === "update" ? { ...(old || {}), ...data } : data);
        return json(res, 200, { ok: 1 });
      }
      if (id !== me.id) return json(res, 403, {});
      if (c === "visitors") { await put({ ...(old || {}), ...data, name: me.name, dc: me.name }); return json(res, 200, { ok: 1 }); }
      if (c === "applications") {
        if (op === "set" && !old) { await put({ ...data, status: "review", chat: [], chatOpen: false, dc: me.name }); return json(res, 200, { ok: 1 }); }
        if (op === "update" && old && old.chatOpen && Array.isArray(data.chat)) {
          const extra = data.chat.slice(old.chat.length, old.chat.length + 1).map(m => ({ t: String(m.t).slice(0, 500), adm: false, ts: Date.now() }));
          await put({ ...old, chat: [...old.chat, ...extra] }); return json(res, 200, { ok: 1 });
        }
        if (op === "update" && old && data.chatOpen === true && Object.keys(data).length === 1) { await put({ ...old, chatOpen: true }); return json(res, 200, { ok: 1 }); }
      }
      return json(res, 403, {});
    }
    json(res, 404, {});
  } catch (e) { json(res, 500, { error: String(e.message || e) }); }
};

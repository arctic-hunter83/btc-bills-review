/**
 * منصّة مطابقة فواتير الاتصالات — الخادم
 * إدارة المنشآت التعليمية · قسم الهندسة والصيانة · مجموعة الهندسة الإلكترونية
 *
 * Deno Deploy + Deno KV. لا قاعدة بيانات خارجية ولا متغيّرات بيئة إلزامية.
 *
 * ما يميّز هذه النسخة عن الصفحة المستقلة:
 *   - كلمات السر تُتحقَّق على الخادم ولا تصل المتصفح أبداً.
 *   - الجلسات في كوكي HttpOnly، والصلاحيات تُفحص على الخادم في كل طلب.
 *   - الحالة مشتركة بين كل الأجهزة والموظفين، لا في متصفح واحد.
 *
 * التشغيل محلياً:  deno task dev
 * الرفع:           ارفع المستودع على GitHub ثم اربطه بـ Deno Deploy (انظر DEPLOY.md)
 */

const kv = await Deno.openKv();

/* ═══════════════ إعدادات ═══════════════ */
const SESSION_HOURS = 12;
const PBKDF2_ITER = 120_000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_TRIES = 8;

/* ═══════════════ أنواع ═══════════════ */
interface User {
  id: string;
  name: string;
  title: string;
  role: "admin" | "user";
  salt: string;
  hash: string;
  mustChange?: boolean;
  createdAt: string;
}
type PublicUser = Omit<User, "salt" | "hash">;

/* ═══════════════ أدوات تشفير ═══════════════ */
const enc = new TextEncoder();
const toHex = (b: ArrayBuffer) =>
  [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) =>
  new Uint8Array((h.match(/../g) ?? []).map((x) => parseInt(x, 16)));

async function derive(password: string, saltHex: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromHex(saltHex), iterations: PBKDF2_ITER, hash: "SHA-256" },
    key, 256,
  );
  return toHex(bits);
}
const newSalt = () => toHex(crypto.getRandomValues(new Uint8Array(16)).buffer);
const newToken = () => toHex(crypto.getRandomValues(new Uint8Array(32)).buffer);

/** مقارنة ثابتة الزمن — لا تكشف طول التطابق. */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ═══════════════ ردود ═══════════════ */
const json = (data: unknown, status = 200, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
const fail = (status: number, error: string) => json({ error }, status);

/* ═══════════════ الجلسات ═══════════════ */
function cookieValue(req: Request, name: string): string | null {
  const raw = req.headers.get("cookie") ?? "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}
function sessionCookie(token: string, maxAgeSeconds: number): string {
  return [
    `sid=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ].join("; ");
}

async function currentUser(req: Request): Promise<User | null> {
  const token = cookieValue(req, "sid");
  if (!token) return null;
  const sess = await kv.get<{ id: string; exp: number }>(["sessions", token]);
  if (!sess.value || sess.value.exp < Date.now()) {
    if (sess.value) await kv.delete(["sessions", token]);
    return null;
  }
  const u = await kv.get<User>(["users", sess.value.id]);
  return u.value ?? null;
}

/** الطلبات المغيِّرة تحتاج ترويسة مخصّصة — يمنع تزوير الطلب من موقع آخر. */
function csrfOk(req: Request): boolean {
  if (req.method === "GET" || req.method === "HEAD") return true;
  return req.headers.get("x-requested-with") === "batelco-platform";
}

/* ═══════════════ البذر ═══════════════ */
async function seedIfEmpty() {
  const existing = kv.list<User>({ prefix: ["users"] });
  for await (const _ of existing) return; // فيه مستخدمون — لا تبذر

  const seed = JSON.parse(await Deno.readTextFile("./seed/staff.json")) as Array<
    { id: string; name: string; title: string; role: "admin" | "user" }
  >;
  for (const p of seed) {
    const salt = newSalt();
    const user: User = {
      id: p.id, name: p.name, title: p.title, role: p.role,
      salt, hash: await derive("Moe@" + p.id, salt),
      mustChange: true, createdAt: new Date().toISOString(),
    };
    await kv.set(["users", p.id], user);
  }
  const pos = JSON.parse(await Deno.readTextFile("./seed/purchase-orders.json")) as
    { active: string; list: Array<Record<string, unknown>> };
  for (const po of pos.list) await kv.set(["po", String(po.po)], po);
  await kv.set(["meta", "activePo"], pos.active);
  console.log(`seeded ${seed.length} users and ${pos.list.length} purchase orders`);
}

/* ═══════════════ قراءة الحالة ═══════════════ */
async function readState() {
  const users: PublicUser[] = [];
  for await (const e of kv.list<User>({ prefix: ["users"] })) {
    const { salt: _s, hash: _h, ...rest } = e.value;
    users.push(rest);
  }
  users.sort((a, b) => a.id.localeCompare(b.id));

  const purchaseOrders: Record<string, unknown> = {};
  for await (const e of kv.list<Record<string, unknown>>({ prefix: ["po"] })) {
    purchaseOrders[String(e.value.po)] = e.value;
  }
  const months: Record<string, unknown> = {};
  for await (const e of kv.list<Record<string, unknown>>({ prefix: ["months"] })) {
    const [, po, m] = e.key as [string, string, string];
    months[`${po}|${m}`] = e.value;
  }
  const active = await kv.get<string>(["meta", "activePo"]);
  return {
    v: 2,
    users,
    purchaseOrders,
    months,
    activePo: active.value ?? Object.keys(purchaseOrders)[0] ?? "",
  };
}

/* ═══════════════ محدودية محاولات الدخول ═══════════════ */
async function tooManyTries(id: string): Promise<boolean> {
  const k = ["login", id];
  const rec = await kv.get<{ n: number; since: number }>(k);
  const now = Date.now();
  if (!rec.value || now - rec.value.since > LOGIN_WINDOW_MS) return false;
  return rec.value.n >= LOGIN_MAX_TRIES;
}
async function noteTry(id: string, ok: boolean) {
  const k = ["login", id];
  if (ok) { await kv.delete(k); return; }
  const rec = await kv.get<{ n: number; since: number }>(k);
  const now = Date.now();
  const fresh = !rec.value || now - rec.value.since > LOGIN_WINDOW_MS;
  await kv.set(k, { n: fresh ? 1 : rec.value!.n + 1, since: fresh ? now : rec.value!.since },
    { expireIn: LOGIN_WINDOW_MS });
}

/* ═══════════════ الموجّه ═══════════════ */
async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  /* ── الواجهة ── */
  if (req.method === "GET" && (path === "/" || path === "/index.html")) {
    const html = await Deno.readTextFile("./static/app.html");
    return new Response(html, {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-cache",
        "x-content-type-options": "nosniff",
        "referrer-policy": "same-origin",
      },
    });
  }
  if (req.method === "GET" && path === "/healthz") return json({ ok: true });

  if (!path.startsWith("/api/")) return fail(404, "not_found");
  if (!csrfOk(req)) return fail(403, "bad_origin");

  /* ── الدخول ── */
  if (path === "/api/login" && req.method === "POST") {
    const { id, password } = await req.json().catch(() => ({}));
    if (typeof id !== "string" || typeof password !== "string") return fail(400, "bad_request");
    if (await tooManyTries(id)) return fail(429, "too_many_attempts");

    const rec = await kv.get<User>(["users", id]);
    const u = rec.value;
    // نشتق دائماً — حتى لا يكشف زمن الرد وجود الحساب من عدمه
    const probeSalt = u?.salt ?? newSalt();
    const attempt = await derive(password, probeSalt);
    const ok = !!u && safeEqual(attempt, u.hash);
    await noteTry(id, ok);
    if (!ok) return fail(401, "bad_credentials");

    const token = newToken();
    const exp = Date.now() + SESSION_HOURS * 3600_000;
    await kv.set(["sessions", token], { id: u!.id, exp }, { expireIn: SESSION_HOURS * 3600_000 });
    const { salt: _s, hash: _h, ...pub } = u!;
    return json({ user: pub }, 200, { "set-cookie": sessionCookie(token, SESSION_HOURS * 3600) });
  }

  if (path === "/api/logout" && req.method === "POST") {
    const token = cookieValue(req, "sid");
    if (token) await kv.delete(["sessions", token]);
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }

  /* ── ما بعده يحتاج جلسة ── */
  const me = await currentUser(req);
  if (!me) return fail(401, "unauthenticated");
  const isAdmin = me.role === "admin";
  const { salt: _ms, hash: _mh, ...mePublic } = me;

  if (path === "/api/me" && req.method === "GET") return json({ user: mePublic });

  if (path === "/api/state" && req.method === "GET") return json(await readState());

  /**
   * حفظ الحالة التشغيلية دفعة واحدة — أوامر الشراء والشهور والأمر النشط.
   * الحسابات لا تُقبل من هنا إطلاقاً: بياناتها ومفاتيحها تُدار عبر /api/users فقط،
   * فلا يستطيع أي طلب ترقية صلاحية نفسه أو المساس بمفاتيح الدخول.
   */
  if (path === "/api/state" && req.method === "PUT") {
    const body = await req.json().catch(() => null);
    if (!body || typeof body !== "object") return fail(400, "bad_request");

    if (body.purchaseOrders && typeof body.purchaseOrders === "object") {
      if (!isAdmin) return fail(403, "forbidden");
      const incoming = body.purchaseOrders as Record<string, { po?: string }>;
      const keep = new Set(Object.keys(incoming));
      for await (const e of kv.list<{ po: string }>({ prefix: ["po"] })) {
        if (!keep.has(e.value.po)) {
          await kv.delete(e.key);
          for await (const m of kv.list({ prefix: ["months", e.value.po] })) await kv.delete(m.key);
        }
      }
      for (const [id, po] of Object.entries(incoming)) await kv.set(["po", id], { ...po, po: id });
    }

    if (body.months && typeof body.months === "object") {
      const incoming = body.months as Record<string, Record<string, unknown>>;
      const keep = new Set(Object.keys(incoming));
      for await (const e of kv.list({ prefix: ["months"] })) {
        const [, po, m] = e.key as [string, string, string];
        if (!keep.has(`${po}|${m}`)) await kv.delete(e.key);
      }
      for (const [key, rec] of Object.entries(incoming)) {
        const i = key.indexOf("|");
        if (i < 0) continue;
        const po = key.slice(0, i), m = key.slice(i + 1);
        await kv.set(["months", po, m], { ...rec, po, month: m });
      }
    }

    if (typeof body.activePo === "string" && body.activePo) {
      await kv.set(["meta", "activePo"], body.activePo);
    }
    return json({ ok: true });
  }

  /* ── تغيير كلمة السر الشخصية ── */
  if (path === "/api/password" && req.method === "POST") {
    const { current, next } = await req.json().catch(() => ({}));
    if (typeof next !== "string" || next.length < 8) return fail(400, "weak_password");
    if (!safeEqual(await derive(String(current ?? ""), me.salt), me.hash)) {
      return fail(403, "bad_current_password");
    }
    const salt = newSalt();
    await kv.set(["users", me.id], {
      ...me, salt, hash: await derive(next, salt), mustChange: false,
    });
    return json({ ok: true });
  }

  /* ── الحسابات (المسؤول) ── */
  if (path === "/api/users" && req.method === "POST") {
    if (!isAdmin) return fail(403, "forbidden");
    const b = await req.json().catch(() => ({}));
    const id = String(b.id ?? "").trim();
    if (!/^\d{4,}$/.test(id)) return fail(400, "bad_id");
    if (!String(b.name ?? "").trim()) return fail(400, "bad_name");
    if (typeof b.password !== "string" || b.password.length < 8) return fail(400, "weak_password");
    if ((await kv.get(["users", id])).value) return fail(409, "duplicate_id");
    const salt = newSalt();
    await kv.set(["users", id], {
      id, name: String(b.name).trim(), title: String(b.title ?? "").trim(),
      role: b.role === "admin" ? "admin" : "user",
      salt, hash: await derive(b.password, salt),
      mustChange: true, createdAt: new Date().toISOString(),
    } satisfies User);
    return json({ ok: true });
  }

  const userMatch = /^\/api\/users\/([^/]+)$/.exec(path);
  if (userMatch) {
    if (!isAdmin) return fail(403, "forbidden");
    const targetId = decodeURIComponent(userMatch[1]);
    const rec = await kv.get<User>(["users", targetId]);
    if (!rec.value) return fail(404, "no_such_user");
    const target = rec.value;

    if (req.method === "PATCH") {
      const b = await req.json().catch(() => ({}));
      const newId = String(b.id ?? target.id).trim();
      if (!/^\d{4,}$/.test(newId)) return fail(400, "bad_id");
      const name = String(b.name ?? target.name).trim();
      if (!name) return fail(400, "bad_name");
      const role = b.role === "admin" ? "admin" : b.role === "user" ? "user" : target.role;
      if (newId !== target.id && (await kv.get(["users", newId])).value) {
        return fail(409, "duplicate_id");
      }
      if (target.role === "admin" && role !== "admin" && (await countAdmins()) <= 1) {
        return fail(409, "last_admin");
      }
      const updated: User = {
        ...target, id: newId, name, title: String(b.title ?? target.title).trim(), role,
      };
      if (newId !== target.id) {
        await kv.delete(["users", target.id]);
        // الجلسات القائمة لهذا الحساب تُبطَل بعد تغيير الرقم
        for await (const e of kv.list<{ id: string }>({ prefix: ["sessions"] })) {
          if (e.value.id === target.id) await kv.delete(e.key);
        }
      }
      await kv.set(["users", newId], updated);
      return json({ ok: true });
    }

    if (req.method === "DELETE") {
      if (targetId === me.id) return fail(409, "self_delete");
      if (target.role === "admin" && (await countAdmins()) <= 1) return fail(409, "last_admin");
      await kv.delete(["users", targetId]);
      for await (const e of kv.list<{ id: string }>({ prefix: ["sessions"] })) {
        if (e.value.id === targetId) await kv.delete(e.key);
      }
      return json({ ok: true });
    }
  }

  const resetMatch = /^\/api\/users\/([^/]+)\/password$/.exec(path);
  if (resetMatch && req.method === "POST") {
    if (!isAdmin) return fail(403, "forbidden");
    const targetId = decodeURIComponent(resetMatch[1]);
    const rec = await kv.get<User>(["users", targetId]);
    if (!rec.value) return fail(404, "no_such_user");
    const { password } = await req.json().catch(() => ({}));
    if (typeof password !== "string" || password.length < 8) return fail(400, "weak_password");
    const salt = newSalt();
    await kv.set(["users", targetId], {
      ...rec.value, salt, hash: await derive(password, salt), mustChange: true,
    });
    return json({ ok: true });
  }

  /* ── أوامر الشراء (المسؤول) ── */
  const poMatch = /^\/api\/po\/([^/]+)$/.exec(path);
  if (poMatch) {
    if (!isAdmin) return fail(403, "forbidden");
    const id = decodeURIComponent(poMatch[1]);
    if (req.method === "PUT") {
      const body = await req.json().catch(() => null);
      if (!body || typeof body !== "object") return fail(400, "bad_request");
      await kv.set(["po", id], { ...body, po: id });
      return json({ ok: true });
    }
    if (req.method === "DELETE") {
      await kv.delete(["po", id]);
      for await (const e of kv.list({ prefix: ["months", id] })) await kv.delete(e.key);
      const active = await kv.get<string>(["meta", "activePo"]);
      if (active.value === id) {
        const first = kv.list<{ po: string }>({ prefix: ["po"] });
        for await (const e of first) { await kv.set(["meta", "activePo"], e.value.po); break; }
      }
      return json({ ok: true });
    }
  }

  if (path === "/api/active-po" && req.method === "PUT") {
    const { po } = await req.json().catch(() => ({}));
    if (!(await kv.get(["po", String(po)])).value) return fail(404, "no_such_po");
    await kv.set(["meta", "activePo"], String(po));
    return json({ ok: true });
  }

  /* ── الشهور ── */
  const monthMatch = /^\/api\/months\/([^/]+)\/([^/]+)$/.exec(path);
  if (monthMatch) {
    const po = decodeURIComponent(monthMatch[1]);
    const month = decodeURIComponent(monthMatch[2]);
    if (req.method === "PUT") {
      const body = await req.json().catch(() => null);
      if (!body || typeof body !== "object") return fail(400, "bad_request");
      await kv.set(["months", po, month], {
        ...body, po, month,
        savedBy: `${me.name} (${me.id})`, savedAt: new Date().toISOString(),
      });
      return json({ ok: true });
    }
    if (req.method === "DELETE") {
      await kv.delete(["months", po, month]);
      return json({ ok: true });
    }
    if (req.method === "PATCH") {
      const rec = await kv.get<Record<string, unknown>>(["months", po, month]);
      if (!rec.value) return fail(404, "no_such_month");
      const { status } = await req.json().catch(() => ({}));
      if (!["passed", "pending", "held"].includes(String(status))) return fail(400, "bad_status");
      await kv.set(["months", po, month], {
        ...rec.value, status,
        statusBy: me.name, statusAt: new Date().toISOString(),
      });
      return json({ ok: true });
    }
  }

  return fail(404, "not_found");
}

async function countAdmins(): Promise<number> {
  let n = 0;
  for await (const e of kv.list<User>({ prefix: ["users"] })) if (e.value.role === "admin") n++;
  return n;
}

await seedIfEmpty();
Deno.serve(handler);

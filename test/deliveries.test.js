/// Teslimat kod havuzu sozlesmesi (Task 1):
/// - POST /api/deliveries/generate alfabe + benzersiz kod uretir.
/// - GET /api/deliveries/pool bos kodlari listeler.
/// - POST /api/deliveries/assign bos kodu okula baglar.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { startServer, adminToken, userToken } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4110); });
after(async () => { await srv.stop(); });

test("admin 10 kod uretir (alfabe + benzersizlik)", async () => {
  const r = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 10 }),
  });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.codes.length, 10);
  assert.ok(data.codes.every((c) => /^[A-HJ-NP-Z2-9]{6}$/.test(c)));
  assert.equal(new Set(data.codes).size, 10);
});

test("alfabe 32 karakterdir (L dahil)", async () => {
  const r = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 300 }),
  });
  assert.equal(r.status, 200);
  const chars = new Set((await r.json()).codes.join("").split(""));
  assert.equal(chars.size, 32);
  assert.ok(chars.has("L"));
});

test("tokensiz generate 401, non-admin 403", async () => {  let r = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ count: 1 }),
  });
  assert.equal(r.status, 401);
  r = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + userToken() },
    body: JSON.stringify({ count: 1 }),
  });
  assert.equal(r.status, 403);
});

test("assign bos kodu okula baglar", async () => {
  const g = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 1 }),
  });
  const code = (await g.json()).codes[0];
  const r = await fetch(srv.base + "/api/deliveries/assign", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code, schoolEmail: "kullanici@test.local", note: "LGS" }),
  });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.status, "atanmis");
  assert.equal(data.schoolEmail, "kullanici@test.local");
});

async function freshCode(note) {
  const g = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 1 }),
  });
  const code = (await g.json()).codes[0];
  await fetch(srv.base + "/api/deliveries/assign", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code, schoolEmail: "kullanici@test.local", note: note || "" }),
  });
  return code;
}

async function confirmAsUser(code, token) {
  return fetch(srv.base + "/api/deliveries/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + (token || userToken()) },
    body: JSON.stringify({ code }),
  });
}

test("okul kendine atanmis kodu onaylar (tek kullanimlik)", async () => {
  const code = await freshCode("paket");
  let r = await confirmAsUser(code);
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.status, "teslim_alindi");
  r = await confirmAsUser(code);
  assert.equal(r.status, 400);
});

test("baskasinin kodu 403 + fail sayaci artmaz", async () => {
  const g = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 1 }),
  });
  const code = (await g.json()).codes[0];
  await fetch(srv.base + "/api/deliveries/assign", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code, schoolEmail: "admin@test.local", note: "" }),
  });
  const r = await confirmAsUser(code);
  assert.equal(r.status, 403);
  const data = await r.json();
  assert.match(data.error, /size atanmad/i);
});

test("alfabe disi kod 400", async () => {
  const r = await confirmAsUser("00II11");
  assert.equal(r.status, 400);
});

test("5 yanlisda 15 dk kilit (dogru kod bile 429)", async () => {
  const code = await freshCode("kilit");
  for (let i = 0; i < 5; i++) {
    const r = await confirmAsUser("ZZZZZ" + "23456"[i]);
    assert.ok([404, 429].includes(r.status));
  }
  const r = await confirmAsUser(code);
  assert.equal(r.status, 429);
});

test("mine yalniz kendi paketlerini listeler", async () => {
  await freshCode("benim");
  const r = await fetch(srv.base + "/api/deliveries/mine", {
    headers: { Authorization: "Bearer " + userToken() },
  });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.ok(data.items.some((x) => x.note === "benim"));
  assert.ok(data.items.every((x) => x.schoolEmail === "kullanici@test.local"));
});

test("mine onaylanmamis kodu maskeli doner", async () => {
  const g = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 1 }),
  });
  const code = (await g.json()).codes[0];
  await fetch(srv.base + "/api/deliveries/assign", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code, schoolEmail: "admin@test.local", note: "maskeli" }),
  });
  const authH = { Authorization: "Bearer " + adminToken() };
  let r = await fetch(srv.base + "/api/deliveries/mine", { headers: authH });
  let item = (await r.json()).items.find((x) => x.note === "maskeli");
  assert.ok(item);
  assert.notEqual(item.code, code);
  assert.equal(item.code.length, 6);
  assert.ok(item.code.startsWith(code.slice(0, 2)));
  r = await fetch(srv.base + "/api/deliveries/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code }),
  });
  assert.equal(r.status, 200);
  r = await fetch(srv.base + "/api/deliveries/mine", { headers: authH });
  item = (await r.json()).items.find((x) => x.note === "maskeli");
  assert.equal(item.code, code);
});
test("print bos + atanmisi QR ile doner, onayliyi vermez", async () => {
  const users = JSON.parse(fs.readFileSync(path.join(srv.dir, "users.json"), "utf-8"));
  users["etiket@test.local"] = { email: "etiket@test.local", role: "lise", profile: { schoolName: "Atatürk Lisesi", district: "Merkez" }, created: 1, lastLogin: null };
  fs.writeFileSync(path.join(srv.dir, "users.json"), JSON.stringify(users, null, 2));
  const g = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 3 }),
  });
  const codes = (await g.json()).codes;
  await fetch(srv.base + "/api/deliveries/assign", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code: codes[0], schoolEmail: "etiket@test.local", note: "" }),
  });
  await fetch(srv.base + "/api/deliveries/assign", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code: codes[1], schoolEmail: "admin@test.local", note: "" }),
  });
  await fetch(srv.base + "/api/deliveries/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code: codes[1] }),
  });
  const r = await fetch(srv.base + "/api/deliveries/print?codes=" + codes.join(","), {
    headers: { Authorization: "Bearer " + adminToken() },
  });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.items.length, 2);
  assert.ok(data.items.every((x) => x.qr.startsWith("data:image/png;base64,")));
  assert.deepEqual(data.items.map((x) => x.code).sort(), [codes[0], codes[2]].sort());
  const atanmis = data.items.find((x) => x.code === codes[0]);
  assert.equal(atanmis.school, "Atatürk Lisesi");
  assert.equal(atanmis.district, "Merkez");
  const bos = data.items.find((x) => x.code === codes[2]);
  assert.equal(bos.school, "");
  assert.equal(bos.district, "");
});

test("yedek deliveries.json icerir", async () => {
  const unzipper = require(path.join(__dirname, "..", "node_modules", "unzipper"));
  const r = await fetch(srv.base + "/api/backup", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ sections: ["deliveries"] }),
  });
  assert.equal(r.status, 200);
  const buf = Buffer.from(await r.arrayBuffer());
  const dir = await unzipper.Open.buffer(buf);
  const names = dir.files.map((f) => f.path);
  assert.ok(names.includes("data/deliveries.json"));
  assert.ok(names.includes("manifest.json"));
});

async function adminPost(p, body) {
  return fetch(srv.base + p, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify(body),
  });
}

test("toplu sil bos + atanmisi siler", async () => {
  const codes = (await (await adminPost("/api/deliveries/generate", { count: 2 })).json()).codes;
  await adminPost("/api/deliveries/assign", { code: codes[0], schoolEmail: "kullanici@test.local", note: "" });
  const r = await adminPost("/api/deliveries/delete", { codes });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.deleted, 2);
  const pool = await (await fetch(srv.base + "/api/deliveries/pool", {
    headers: { Authorization: "Bearer " + adminToken() },
  })).json();
  assert.ok(!pool.codes.some((c) => c.code === codes[1]));
});

test("unassign atamayi havuza dondurur", async () => {
  const code = (await (await adminPost("/api/deliveries/generate", { count: 1 })).json()).codes[0];
  await adminPost("/api/deliveries/assign", { code, schoolEmail: "kullanici@test.local", note: "X" });
  const r = await adminPost("/api/deliveries/unassign", { code });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).status, "bos");
  const list = await (await fetch(srv.base + "/api/deliveries", {
    headers: { Authorization: "Bearer " + adminToken() },
  })).json();
  const back = list.items.find((x) => x.code === code);
  assert.ok(back);
  assert.equal(back.status, "bos");
  assert.equal(back.schoolEmail, null);
});

test("onaylanmis kayit cozulmez/silinemez", async () => {
  const code = (await (await adminPost("/api/deliveries/generate", { count: 1 })).json()).codes[0];
  await adminPost("/api/deliveries/assign", { code, schoolEmail: "admin@test.local", note: "" });
  await fetch(srv.base + "/api/deliveries/confirm", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ code }),
  });
  const u = await adminPost("/api/deliveries/unassign", { code });
  assert.equal(u.status, 400);
  const d = await adminPost("/api/deliveries/delete", { codes: [code] });
  assert.equal((await d.json()).deleted, 0);
});
test("confirm 15dk/20 hiz sinirina takilir", async () => {
  // Bicim-disi kodlar kilide dokunmaz ama limiter sayacina girer; IP sayaci onceki 10 confirmde.
  const jwt = require(path.join(__dirname, "..", "node_modules", "jsonwebtoken"));
  const { TEST_SECRET } = require("./helpers");
  const fresh = jwt.sign({ email: "limit@test.local", role: "lise" }, TEST_SECRET, { expiresIn: "10m" });
  const sts = [];
  for (let i = 0; i < 25; i++) {
    const r = await fetch(srv.base + "/api/deliveries/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + fresh },
      body: JSON.stringify({ code: "00II" + String(i).padStart(2, "0") }),
    });
    sts.push(r.status);
  }
  assert.equal(sts[0], 400);
  assert.equal(sts[10], 429);
});

async function bulkAssign(body) {
  const r = await fetch(srv.base + "/api/deliveries/bulk", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify(body),
  });
  return { status: r.status, data: await r.json() };
}

test("bulk filtreye uyan okullara atar, uymayana atmaz", async () => {
  const users = JSON.parse(fs.readFileSync(path.join(srv.dir, "users.json"), "utf-8"));
  users["resmi@test.local"] = { email: "resmi@test.local", role: "lise", profile: { ownership: "resmi" }, created: 1, lastLogin: null };
  users["ozel@test.local"] = { email: "ozel@test.local", role: "ortaokul", profile: { ownership: "ozel" }, created: 1, lastLogin: null };
  fs.writeFileSync(path.join(srv.dir, "users.json"), JSON.stringify(users, null, 2));
  const { status, data } = await bulkAssign({ ownership: "resmi", roles: ["lise", "ortaokul"], note: "T" });
  assert.equal(status, 200);
  assert.equal(data.assigned, 1);
  assert.equal(data.codes.length, 1);
  const list = await (await fetch(srv.base + "/api/deliveries", {
    headers: { Authorization: "Bearer " + adminToken() },
  })).json();
  const got = list.items.filter((x) => x.status === "atanmis" && x.note === "T").map((x) => x.schoolEmail);
  assert.deepEqual(got, ["resmi@test.local"]);
});

test("bulk bekleyeni olana da ikinci kodu atar", async () => {
  const before = (await (await fetch(srv.base + "/api/deliveries", {
    headers: { Authorization: "Bearer " + adminToken() },
  })).json()).items.filter((x) => x.schoolEmail === "kullanici@test.local" && x.status === "atanmis").length;
  const { status, data } = await bulkAssign({ ownership: "all", roles: [] });
  assert.equal(status, 200);
  assert.ok(data.assigned >= 3);
  const after = (await (await fetch(srv.base + "/api/deliveries", {
    headers: { Authorization: "Bearer " + adminToken() },
  })).json()).items.filter((x) => x.schoolEmail === "kullanici@test.local" && x.status === "atanmis").length;
  assert.equal(after, before + 1);
});

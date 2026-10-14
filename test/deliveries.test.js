/// Teslimat kod havuzu sozlesmesi (Task 1):
/// - POST /api/deliveries/generate alfabe + benzersiz kod uretir.
/// - GET /api/deliveries/pool bos kodlari listeler.
/// - POST /api/deliveries/assign bos kodu okula baglar.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
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

test("tokensiz generate 401, non-admin 403", async () => {
  let r = await fetch(srv.base + "/api/deliveries/generate", {
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

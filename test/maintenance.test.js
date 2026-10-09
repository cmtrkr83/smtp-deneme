/// Bakım modu sözleşmesi:
/// - Açıkken admin dışı send-otp → 503 (e-posta GÖNDERİLMEDEN).
/// - verify-otp bilerek engellenmez (503 değil, normal akış).
/// - Kapalıyken kayıtsız e-posta sahte-başarı döner (kullanıcı sayımı engeli).
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startServer, adminToken, solveCaptcha } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4104); });
after(async () => { await srv.stop(); });

async function sendOtp(email) {
  const cap = await solveCaptcha(srv.base);
  return fetch(srv.base + "/api/send-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, captchaId: cap.id, captcha: cap.code }),
  });
}

test("bakım kapalıyken kayıtsız e-posta sahte-başarı döner (sayım engeli)", async () => {
  const r = await sendOtp("yok@test.local");
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.ok(data.expiresIn > 0);
});

test("bakım açıkken kayıtlı non-admin 503 alır", async () => {
  let r = await fetch(srv.base + "/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ maintenance: true }),
  });
  assert.equal(r.status, 200);

  r = await sendOtp("kullanici@test.local");
  assert.equal(r.status, 503);
  const data = await r.json();
  assert.equal(data.maintenance, true);
});

test("bakım açıkken kayıtsız e-posta da 503 alır (kullanıcı sayımı sinyali yok)", async () => {
  const r = await sendOtp("yok@test.local");
  assert.equal(r.status, 503);
});

test("bakım açıkken verify-otp engellenmez (503 değil)", async () => {
  const r = await fetch(srv.base + "/api/verify-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "kullanici@test.local", otp: "000000" }),
  });
  assert.notEqual(r.status, 503);
  assert.equal(r.status, 400);
});

test("bakım kapatılınca non-admin OTP akışına döner (sahte-başarı)", async () => {
  const r0 = await fetch(srv.base + "/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ maintenance: false }),
  });
  assert.equal(r0.status, 200);
  const r = await sendOtp("yok2@test.local");
  assert.equal(r.status, 200);
});

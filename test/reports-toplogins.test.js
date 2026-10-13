/// Raporlar en-cok-giris sozlesmesi:
/// - GET /api/reports yanitinda topLogins: [{ email, school, count }] olur.
/// - Sadece login kayitlari sayilir, admin harictir, coktan aza siralidir.
/// - school yoksa e-posta kullanilir.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { startServer, adminToken } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4108); });
after(async () => { await srv.stop(); });

test("reports topLogins doner (admin haric, okul adiyla)", async () => {
  const users = JSON.parse(fs.readFileSync(path.join(srv.dir, "users.json"), "utf-8"));
  users["okul@test.local"] = { email: "okul@test.local", role: "lise", profile: { schoolName: "Atatürk Lisesi" }, created: 1, lastLogin: null };
  users["sade@test.local"] = { email: "sade@test.local", role: "ortaokul", created: 1, lastLogin: null };
  fs.writeFileSync(path.join(srv.dir, "users.json"), JSON.stringify(users, null, 2));

  const logs = [];
  const login = (user, n) => {
    for (let i = 0; i < n; i++) {
      logs.push({ id: "t" + user + i, timestamp: Date.now(), action: "login", user, detail: user + " giris", ip: "?", xff: "-" });
    }
  };
  login("admin@test.local", 5);
  login("okul@test.local", 4);
  login("sade@test.local", 2);
  logs.push({ id: "other", timestamp: Date.now(), action: "announcement_create", user: "okul@test.local", detail: "x", ip: "?", xff: "-" });
  fs.writeFileSync(path.join(srv.dir, "logs.json"), JSON.stringify({ logs }, null, 2));

  const r = await fetch(srv.base + "/api/reports", {
    headers: { Authorization: "Bearer " + adminToken() },
  });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.deepEqual(data.topLogins, [
    { email: "okul@test.local", school: "Atatürk Lisesi", count: 4 },
    { email: "sade@test.local", school: "sade@test.local", count: 2 },
  ]);
});

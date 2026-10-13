/// Raporlar okul dagilimi sozlesmesi:
/// - GET /api/reports yanitinda schools: { total, resmi, ozel, belirsiz } olur.
/// - Admin haric kullanicilar profile.ownership alanina gore sayilir.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { startServer, adminToken, userToken } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4107); });
after(async () => { await srv.stop(); });

async function getReports(token) {
  const headers = token ? { Authorization: "Bearer " + token } : {};
  const r = await fetch(srv.base + "/api/reports", { headers });
  return { status: r.status, data: await r.json() };
}

test("reports schools kirilimi doner (seed: 1 belirsiz okul)", async () => {
  const { status, data } = await getReports(adminToken());
  assert.equal(status, 200);
  assert.deepEqual(data.schools, { total: 1, resmi: 0, ozel: 0, belirsiz: 1 });
});

test("ownership yazilan kullanicilar ture gore sayilir", async () => {
  const f = path.join(srv.dir, "users.json");
  const users = JSON.parse(fs.readFileSync(f, "utf-8"));
  users["resmi@test.local"] = { email: "resmi@test.local", role: "lise", profile: { ownership: "resmi" }, created: 1, lastLogin: null };
  users["ozel@test.local"] = { email: "ozel@test.local", role: "ortaokul", profile: { ownership: "ozel" }, created: 1, lastLogin: null };
  fs.writeFileSync(f, JSON.stringify(users, null, 2));

  const { status, data } = await getReports(adminToken());
  assert.equal(status, 200);
  assert.deepEqual(data.schools, { total: 3, resmi: 1, ozel: 1, belirsiz: 1 });
});

test("reports admin disi tokenda 403 doner", async () => {
  const { status } = await getReports(userToken());
  assert.equal(status, 403);
});

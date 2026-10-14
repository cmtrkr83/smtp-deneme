/// Modul ac/kapa sozlesmesi:
/// - Kapali modulde non-admin 403 + "kullanima kapatilmistir" mesaji alir.
/// - Admin etkilenmez; acilinca erisim doner.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { startServer, adminToken, userToken } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4111); });
after(async () => { await srv.stop(); });

const ROUTES = {
  announcements: "/api/announcements",
  surveys: "/api/surveys",
  files: "/api/files",
  "file-requests": "/api/file-requests",
  requests: "/api/requests",
  deliveries: "/api/deliveries/mine",
};

async function get(route, token) {
  const r = await fetch(srv.base + route, {
    headers: { Authorization: "Bearer " + token },
  });
  return { status: r.status, data: await r.json().catch(() => ({})) };
}

async function setModules(modules) {
  const r = await fetch(srv.base + "/api/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ maintenance: false, modules }),
  });
  assert.equal(r.status, 200);
  return r.json();
}

const ALL_OPEN = Object.fromEntries(Object.keys(ROUTES).map((k) => [k, true]));

test("varsayilanda tum moduller acik", async () => {
  for (const route of Object.values(ROUTES)) {
    const { status } = await get(route, userToken());
    assert.equal(status, 200);
  }
});

test("kapali modulde kullanici 403 + mesaj, admin 200", async () => {
  for (const key of Object.keys(ROUTES)) {
    await setModules({ ...ALL_OPEN, [key]: false });
    const u = await get(ROUTES[key], userToken());
    assert.equal(u.status, 403);
    assert.match(u.data.error || "", /kullanıma kapatılmıştır/);
    const a = await get(ROUTES[key], adminToken());
    assert.equal(a.status, 200);
  }
  await setModules(ALL_OPEN);
  for (const route of Object.values(ROUTES)) {
    const { status } = await get(route, userToken());
    assert.equal(status, 200);
  }
});

test("status modulleri herkese acar", async () => {
  await setModules({ ...ALL_OPEN, surveys: false });
  const r = await fetch(srv.base + "/api/status");
  const data = await r.json();
  assert.equal(data.modules.surveys, false);
  assert.equal(data.modules.announcements, true);
  await setModules(ALL_OPEN);
});

/// Takvim etkinlikleri sözleşmesi:
/// - Okuma dahil tümü token ister (yoksa 401).
/// - Yazma (POST/PUT/DELETE) yalnızca admin (değilse 403, veri değişmez).
/// - Başlık zorunlu; tarih YYYY-MM-DD; endDate < startDate ise 400.
/// - Bilinmeyen id'de PUT/DELETE 404.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { startServer, adminToken, userToken } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4106); });
after(async () => { await srv.stop(); });

const adminH = () => ({ "Content-Type": "application/json", Authorization: "Bearer " + adminToken() });
const userH = () => ({ "Content-Type": "application/json", Authorization: "Bearer " + userToken() });

async function postEvent(body, headers) {
  return fetch(srv.base + "/api/events", {
    method: "POST",
    headers: headers || adminH(),
    body: JSON.stringify(body),
  });
}

test("tokensiz GET 401", async () => {
  const r = await fetch(srv.base + "/api/events");
  assert.equal(r.status, 401);
});

test("tokensiz POST 401", async () => {
  const r = await fetch(srv.base + "/api/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: "X", startDate: "2026-10-12" }),
  });
  assert.equal(r.status, 401);
});

test("non-admin POST 403, dosya değişmez", async () => {
  const before = fs.existsSync(path.join(srv.dir, "events.json"))
    ? fs.readFileSync(path.join(srv.dir, "events.json"), "utf8")
    : null;
  const r = await postEvent({ title: "Yetkisiz", startDate: "2026-10-12" }, userH());
  assert.equal(r.status, 403);
  const after = fs.existsSync(path.join(srv.dir, "events.json"))
    ? fs.readFileSync(path.join(srv.dir, "events.json"), "utf8")
    : null;
  assert.equal(after, before);
});

test("400: başlıksız + bozuk tarih + endDate<startDate", async () => {
  let r = await postEvent({ startDate: "2026-10-12" });
  assert.equal(r.status, 400);
  r = await postEvent({ title: "Bozuk", startDate: "12-10-2026" });
  assert.equal(r.status, 400);
  r = await postEvent({ title: "Ters", startDate: "2026-10-14", endDate: "2026-10-12" });
  assert.equal(r.status, 400);
});

test("CRUD + sıralı listeleme + events.json'a yazıldı", async () => {
  const a = await (await postEvent({ title: "Sonraki", startDate: "2026-11-01", description: "d2" })).json();
  const b = await (await postEvent({ title: "Önceki", startDate: "2026-10-10", endDate: "2026-10-12", description: "d1" })).json();
  assert.ok(a.id && b.id);

  const list = (await (await fetch(srv.base + "/api/events", { headers: adminH() })).json()).events;
  assert.equal(list.length, 2);
  assert.equal(list[0].id, b.id);
  assert.equal(list[1].id, a.id);
  assert.equal(list[0].endDate, "2026-10-12");

  const raw = JSON.parse(fs.readFileSync(path.join(srv.dir, "events.json"), "utf8"));
  assert.ok(Array.isArray(raw.events) && raw.events.length === 2);

  const upd = await (await fetch(srv.base + "/api/events/" + b.id, {
    method: "PUT", headers: adminH(), body: JSON.stringify({ title: "Güncel" }),
  })).json();
  assert.equal(upd.title, "Güncel");

  const del = await fetch(srv.base + "/api/events/" + a.id, { method: "DELETE", headers: adminH() });
  assert.equal(del.status, 200);
  const left = (await (await fetch(srv.base + "/api/events", { headers: adminH() })).json()).events;
  assert.equal(left.length, 1);
  assert.equal(left[0].id, b.id);
});

test("PUT/DELETE bilinmeyen id 404", async () => {
  let r = await fetch(srv.base + "/api/events/yok123", { method: "PUT", headers: adminH(), body: JSON.stringify({ title: "X" }) });
  assert.equal(r.status, 404);
  r = await fetch(srv.base + "/api/events/yok123", { method: "DELETE", headers: adminH() });
  assert.equal(r.status, 404);
});

test("log'a event_add işlendi", async () => {
  const data = await (await fetch(srv.base + "/api/logs", { headers: adminH() })).json();
  const logs = data.list || data.logs || data;
  assert.ok(logs.some((l) => l.action === "event_add"));
});

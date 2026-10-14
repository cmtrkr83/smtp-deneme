/// Kullanici hizli erisim highlight sozlesmesi:
/// - Bekleyen is varsa ilgili kart highlight:true (kirmizi + pulse).
/// - Islem yapilinca highlight kalkar.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { startServer, userToken } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4109); });
after(async () => { await srv.stop(); });

const ME = "kullanici@test.local";
const FUTURE = Date.now() + 30 * 24 * 60 * 60 * 1000;

function write(name, obj) {
  fs.writeFileSync(path.join(srv.dir, name), JSON.stringify(obj, null, 2));
}

async function dashboard() {
  const r = await fetch(srv.base + "/api/dashboard", {
    headers: { Authorization: "Bearer " + userToken() },
  });
  assert.equal(r.status, 200);
  return r.json();
}

function byTitle(data, title) {
  const l = data.links.find((x) => x.title === title);
  assert.ok(l, title + " karti yok");
  return l;
}

test("bekleyen islerde kartlar highlight olur", async () => {
  write("announcements.json", { announcements: [{ id: "a1", title: "D", content: "x", target: "all", expiresAt: FUTURE, readBy: [] }] });
  write("surveys.json", { surveys: [{ id: "s1", title: "S", targetType: "all", expiresAt: FUTURE, questions: [] }] });
  write("files.json", { files: [{ id: "f1", targetType: "all", startsAt: 0, expiresAt: FUTURE, downloads: [] }] });
  write("requests.json", { requests: [{ id: "r1", status: "open", submittedBy: ME }] });

  const data = await dashboard();
  assert.equal(byTitle(data, "Duyurular").highlight, true);
  assert.equal(byTitle(data, "Veri Toplama").highlight, true);
  assert.equal(byTitle(data, "Dosya Dağıtım").highlight, true);
  assert.equal(byTitle(data, "Talep/İtiraz").highlight, true);
});

test("islemler yapilinca highlight kalkar", async () => {
  write("announcements.json", { announcements: [{ id: "a1", title: "D", content: "x", target: "all", expiresAt: FUTURE, readBy: [ME] }] });
  write("responses.json", { responses: [{ surveyId: "s1", userId: ME }] });
  write("files.json", { files: [{ id: "f1", targetType: "all", startsAt: 0, expiresAt: FUTURE, downloads: [{ userId: ME }] }] });
  write("requests.json", { requests: [{ id: "r1", status: "closed", submittedBy: ME }] });

  const data = await dashboard();
  assert.equal(byTitle(data, "Duyurular").highlight, undefined);
  assert.equal(byTitle(data, "Veri Toplama").highlight, undefined);
  assert.equal(byTitle(data, "Dosya Dağıtım").highlight, undefined);
  assert.equal(byTitle(data, "Talep/İtiraz").highlight, undefined);
});

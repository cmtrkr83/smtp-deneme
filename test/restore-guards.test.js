/// Yedek geri yükleme korumaları (Parça 1 regresyon kilidi):
/// - Zip Slip: ../ içeren arşiv çıkarmadan reddedilir, canlı veri değişmez.
/// - Boş-bölüm koruması: yedekte olmayan uploads klasörü silinmez.
/// - Manifestsiz zip reddedilir. Yetkisiz erişim 401/403.
"use strict";

const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const { startServer, adminToken, userToken } = require("./helpers");

let srv;
before(async () => { srv = await startServer(4105); });
after(async () => { await srv.stop(); });

function readJson(name) {
  return fs.readFileSync(path.join(srv.dir, name), "utf-8");
}

/// Ham stored-zip yazıcı: archiver ../ yolları temizlediği için kötü niyetli
/// girdiyi ham baytla kurar (sıkıştırmasız, crc32 ile).
const CRC = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function rawZip(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const [name, content] of entries) {
    const data = Buffer.from(content);
    const nb = Buffer.from(name);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(0, 8); lh.writeUInt16LE(0, 10); lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc32(data), 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nb.length, 26); lh.writeUInt16LE(0, 28);
    chunks.push(lh, nb, data);
    central.push({ nb, crc: crc32(data), len: data.length, offset });
    offset += lh.length + nb.length + data.length;
  }
  const cdStart = offset;
  let cdLen = 0;
  for (const e of central) {
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 12); ch.writeUInt32LE(e.crc, 16);
    ch.writeUInt32LE(e.len, 20); ch.writeUInt32LE(e.len, 24);
    ch.writeUInt16LE(e.nb.length, 28); ch.writeUInt32LE(e.offset, 42);
    chunks.push(ch, e.nb);
    cdLen += ch.length + e.nb.length;
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(central.length, 8);
  end.writeUInt16LE(central.length, 10); end.writeUInt32LE(cdLen, 12);
  end.writeUInt32LE(cdStart, 16);
  chunks.push(end);
  return Buffer.concat(chunks);
}

function archiverZip(entries) {
  const { ZipArchive } = require(path.join(__dirname, "..", "node_modules", "archiver"));
  return new Promise((resolve, reject) => {
    const arch = new ZipArchive();
    const bufs = [];
    arch.on("data", (d) => bufs.push(d));
    arch.on("error", reject);
    arch.on("end", () => resolve(Buffer.concat(bufs)));
    for (const [name, content] of entries) arch.append(content, { name });
    arch.finalize();
  });
}

async function postRestore(token, zipBuffer) {
  const form = new FormData();
  if (zipBuffer) form.append("file", new Blob([zipBuffer]), "yedek-test.zip");
  const headers = {};
  if (token) headers.Authorization = "Bearer " + token;
  return fetch(srv.base + "/api/backup/restore", { method: "POST", headers, body: zipBuffer ? form : undefined });
}

test("tokensuz restore 401", async () => {
  const r = await postRestore(null, null);
  assert.equal(r.status, 401);
});

test("non-admin restore 403", async () => {
  const r = await postRestore(userToken(), null);
  assert.equal(r.status, 403);
});

test("Zip Slip: ../ içeren arşiv reddedilir, veri değişmez", async () => {
  const before = readJson("users.json");
  const evilOutside = path.join(os.tmpdir(), "EVIL_RT_SHOULD_NOT_EXIST.txt");
  const zip = rawZip([
    ["../EVIL_RT_SHOULD_NOT_EXIST.txt", "pwned"],
    ["manifest.json", JSON.stringify({ app: "smtp-otp-login", sections: ["settings"] })],
  ]);
  const r = await postRestore(adminToken(), zip);
  assert.equal(r.status, 400);
  const data = await r.json();
  assert.match(data.error, /izin dışı/);
  assert.equal(readJson("users.json"), before);
  assert.ok(!fs.existsSync(evilOutside));
});

test("manifestsiz zip reddedilir, veri değişmez", async () => {
  const before = readJson("settings.json");
  const zip = await archiverZip([["data/settings.json", "{}"]]);
  const r = await postRestore(adminToken(), zip);
  assert.equal(r.status, 400);
  assert.equal(readJson("settings.json"), before);
});

test("yedekte olmayan uploads korunur + JSON uygulanır", async () => {
  const zip = await archiverZip([
    ["manifest.json", JSON.stringify({ app: "smtp-otp-login", sections: ["file-requests"] })],
    ["data/file-requests.json", JSON.stringify({ requests: [{ id: "r1" }] })],
  ]);
  const r = await postRestore(adminToken(), zip);
  assert.equal(r.status, 200);
  assert.deepEqual(JSON.parse(readJson("file-requests.json")), { requests: [{ id: "r1" }] });
  assert.equal(fs.readFileSync(path.join(srv.dir, "uploads", "file-requests", "canli.txt"), "utf-8"), "canli veri");
});

test("yedekteki uploads normal şekilde geri yüklenir", async () => {
  const zip = await archiverZip([
    ["manifest.json", JSON.stringify({ app: "smtp-otp-login", sections: ["file-requests"] })],
    ["data/file-requests.json", JSON.stringify({ requests: [] })],
    ["uploads/file-requests/yeni.txt", "yedekten"],
  ]);
  const r = await postRestore(adminToken(), zip);
  assert.equal(r.status, 200);
  assert.equal(fs.readFileSync(path.join(srv.dir, "uploads", "file-requests", "yeni.txt"), "utf-8"), "yedekten");
});

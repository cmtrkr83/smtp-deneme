/// Canlı veriye dokunmayan e2e iskeleti: geçici DATA_DIR + ayrı portta sunucu.
/// SMTP'ye hiç girilmez: e-posta gönderen yollara test senaryosu sokulmaz.
"use strict";

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REPO = path.join(__dirname, "..");
const jwt = require(path.join(REPO, "node_modules", "jsonwebtoken"));

const TEST_SECRET = "test-secret-12345";

function seedDataDir(dir) {
  fs.mkdirSync(path.join(dir, "uploads", "file-requests"), { recursive: true });
  const files = {
    "users.json": {
      "admin@test.local": { email: "admin@test.local", role: "admin", created: 1, lastLogin: null },
      "kullanici@test.local": { email: "kullanici@test.local", role: "lise", created: 1, lastLogin: null },
    },
    "settings.json": { maintenance: false },
    "announcements.json": { announcements: [] },
    "surveys.json": { surveys: [] },
    "responses.json": { responses: [] },
    "file-requests.json": { requests: [] },
    "requests.json": { requests: [] },
    "logs.json": { logs: [] },
    "files.json": { files: [] },
  };
  for (const [name, obj] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), JSON.stringify(obj, null, 2));
  }
  fs.writeFileSync(path.join(dir, "uploads", "file-requests", "canli.txt"), "canli veri");
}

async function waitReady(base, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(base + "/api/status");
      if (r.ok) return;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error("sunucu hazir olmadi: " + base);
}

async function startServer(port) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "smtp-test-"));
  seedDataDir(dir);
  const child = spawn(process.execPath, ["server.js"], {
    cwd: REPO,
    env: { ...process.env, PORT: String(port), DATA_DIR: dir, JWT_SECRET: TEST_SECRET },
    stdio: "ignore",
  });
  const base = "http://127.0.0.1:" + port;
  await waitReady(base);
  return {
    base,
    dir,
    async stop() {
      child.kill();
      await new Promise((r) => setTimeout(r, 300));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

function adminToken() {
  return jwt.sign({ email: "admin@test.local", role: "admin" }, TEST_SECRET, { expiresIn: "10m" });
}

function userToken() {
  return jwt.sign({ email: "kullanici@test.local", role: "lise" }, TEST_SECRET, { expiresIn: "10m" });
}

/// Captcha SVG'sindeki 5 haneyi sirayla okur (sunucu her haneyi ayri <text> yazar).
async function solveCaptcha(base) {
  const r = await fetch(base + "/api/captcha");
  const data = await r.json();
  const digits = [...data.svg.matchAll(/<text[^>]*>(\d)<\/text>/g)].map((m) => m[1]).join("");
  if (digits.length !== 5) throw new Error("captcha cozuleMEdi");
  return { id: data.id, code: digits };
}

module.exports = { startServer, adminToken, userToken, solveCaptcha, TEST_SECRET };

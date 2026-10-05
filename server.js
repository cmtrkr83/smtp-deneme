require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const multer = require("multer");

const app = express();

// Sayiya degil ozel-ag araliklarina guven: soketten baslayip tum ic ag
// halkalari (docker, NAT, sanal ag) atlanir, ilk herkese acik IP bulunur.
// Halka sayisi degisse de (Windows NAT + nginx + olasi ara proxy) dogru calisir.
app.set("trust proxy", ["loopback", "linklocal", "uniquelocal", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
app.use(helmet({
  contentSecurityPolicy: {
    // Rapor modu: HICBIR SEYI ENGELLEMEZ, sadece ihlalleri /api/csp-report'a bildirir.
    // Mevcut inline script + CDN kullanimiyla tam uyumlu politika; sikilastirma sonraki adim.
    reportOnly: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com", "data:"],
      "img-src": ["'self'", "data:", "blob:"],
      "connect-src": ["'self'"],
      "frame-src": ["blob:"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "report-uri": ["/api/csp-report"],
    },
  },
}));
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

// Aktiflik takibi: token'li her istekte son gorulme guncellenir (throttled, admin paneli icin)
app.use((req, res, next) => {
  try {
    const h = req.headers.authorization;
    if (h && h.startsWith("Bearer ")) {
      const d = jwt.verify(h.split(" ")[1], JWT_SECRET);
      if (d && d.email) touchPresence(String(d.email).toLowerCase().trim());
    }
  } catch (_) {}
  next();
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const USERS_FILE = path.join(DATA_DIR, "users.json");
const ANNOUNCEMENTS_FILE = path.join(DATA_DIR, "announcements.json");
const LOGS_FILE = path.join(DATA_DIR, "logs.json");
const FILES_FILE = path.join(DATA_DIR, "files.json");
const FILE_REQUESTS_FILE = path.join(DATA_DIR, "file-requests.json");
const UPLOADS_DIR = path.join(DATA_DIR, "uploads");
const PRESENCE_FILE = path.join(DATA_DIR, "presence.json");
const PRESENCE_TOUCH_MS = 60 * 1000; // kullanici basina yazma sikligi
const PRESENCE_SAVE_MS = 20 * 1000; // diske yazma araligi (debounce)
const PRESENCE_TTL_MS = 2 * 60 * 60 * 1000; // budama suresi
// Atomik JSON yazma: tmp dosyaya yaz + rename (yarım yazma / 0-bayt bozulmayı önler)
function atomicSaveJson(filePath, data) {
  const tmp = filePath + ".tmp-" + process.pid;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, filePath);
}
let presenceMap = null;
let presenceSaveTimer = null;
function loadPresence() {
  if (presenceMap) return presenceMap;
  try {
    if (fs.existsSync(PRESENCE_FILE)) {
      const raw = JSON.parse(fs.readFileSync(PRESENCE_FILE, "utf-8"));
      presenceMap = raw && typeof raw === "object" ? raw : {};
    } else {
      presenceMap = {};
    }
  } catch (_) {
    presenceMap = {};
  }
  return presenceMap;
}
function savePresence() {
  presenceSaveTimer = null;
  try {
    const now = Date.now();
    const map = loadPresence();
    for (const k of Object.keys(map)) {
      if (!map[k] || now - map[k] > PRESENCE_TTL_MS) delete map[k];
    }
    atomicSaveJson(PRESENCE_FILE, JSON.stringify(map));
  } catch (_) {}
}
function touchPresence(email) {
  if (!email) return;
  const now = Date.now();
  const map = loadPresence();
  if (map[email] && now - map[email] < PRESENCE_TOUCH_MS) return;
  map[email] = now;
  if (!presenceSaveTimer) presenceSaveTimer = setTimeout(savePresence, PRESENCE_SAVE_MS);
}
function countPresence(minutes) {
  const cutoff = Date.now() - minutes * 60 * 1000;
  return Object.values(loadPresence()).filter((ts) => ts >= cutoff).length;
}

function seedInitialAdmin() {
  const users = loadUsers();
  if (Object.keys(users).length === 0 && ADMIN_EMAIL) {
    const normEmail = ADMIN_EMAIL.toLowerCase().trim();
    users[normEmail] = {
      email: normEmail,
      role: "admin",
      created: Date.now(),
      lastLogin: null,
    };
    saveUsers(users);
    console.log(`[INIT] Admin kullanici olusturuldu: ${normEmail}`);
  }
}

if (!JWT_SECRET || JWT_SECRET === "degistirin-buraya-gizli-anahtar-yazin") {
  console.warn("[UYARI] JWT_SECRET zayif! .env dosyasinda guclu bir anahtar belirleyin.");
}

const OTP_EXPIRY_MS = 3 * 60 * 1000;
const OTP_COOLDOWN_MS = 60 * 1000;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 3 * 60 * 1000;

const otpStore = new Map();
const lastOtpRequest = new Map();
const failedAttempts = new Map();
const captchaStore = new Map();

const CAPTCHA_EXPIRY_MS = 5 * 60 * 1000;

// Captcha cleanup every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [id, data] of captchaStore) {
    if (now - data.createdAt > CAPTCHA_EXPIRY_MS) captchaStore.delete(id);
  }
}, 10 * 60 * 1000);

function generateCaptchaSvg(text) {
  const width = 160;
  const height = 54;
  const colors = ["#2563eb","#dc2626","#16a34a","#d97706","#7c3aed","#0891b2"];
  let svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;
  svg += `<rect width="${width}" height="${height}" fill="#f9fafb" rx="6"/>`;
  for (let i = 0; i < 6; i++) {
    const x1 = Math.random() * width;
    const y1 = Math.random() * height;
    const x2 = Math.random() * width;
    const y2 = Math.random() * height;
    svg += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#d1d5db" stroke-width="1.5" opacity="0.6"/>`;
  }
  for (let i = 0; i < 20; i++) {
    const cx = Math.random() * width;
    const cy = Math.random() * height;
    svg += `<circle cx="${cx}" cy="${cy}" r="${1+Math.random()*2}" fill="#9ca3af" opacity="0.4"/>`;
  }
  text.split("").forEach((ch, i) => {
    const x = 14 + i * 30;
    const y = 34 + (Math.random() - 0.5) * 14;
    const angle = (Math.random() - 0.5) * 35;
    const color = colors[i % colors.length];
    svg += `<text x="${x}" y="${y}" transform="rotate(${angle.toFixed(1)},${x},${y})" font-family="Arial,sans-serif" font-size="30" font-weight="bold" fill="${color}">${ch}</text>`;
  });
  svg += "</svg>";
  return svg;
}

function loadUsers() {
  try {
    if (fs.existsSync(USERS_FILE)) {
      return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
    }
  } catch (_) {}
  return {};
}

function saveUsers(users) {
  atomicSaveJson(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadAnnouncements() {
  try {
    if (fs.existsSync(ANNOUNCEMENTS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(ANNOUNCEMENTS_FILE, "utf-8"));
      return Array.isArray(raw.announcements) ? raw.announcements : [];
    }
  } catch (_) {}
  return [];
}

function saveAnnouncements(list) {
  atomicSaveJson(ANNOUNCEMENTS_FILE, JSON.stringify({ announcements: list }, null, 2));
}

function loadLogs() {
  try {
    if (fs.existsSync(LOGS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(LOGS_FILE, "utf-8"));
      return Array.isArray(raw.logs) ? raw.logs : [];
    }
  } catch (_) {}
  return [];
}

function appendLog(entry) {
  const list = loadLogs();
  list.push(entry);
  if (list.length > 10000) list.splice(0, list.length - 10000);
  atomicSaveJson(LOGS_FILE, JSON.stringify({ logs: list }, null, 2));
}

function clientIp(req) {
  // Guvenilir cozum: Express "trust proxy" ayarini kullanarak proxy
  // zincirini cozer. Ham XFF basliginin en solu kullanilmaz cunku
  // istemci tarafindan sahtecilikle (spoof) yazilabilir ve loglari
  // delil niteliginden dusurur.
  const clean = (ip) => {
    const s = String(ip || "").trim();
    if (!s) return "";
    return s.startsWith("::ffff:") ? s.slice(7) : s;
  };
  try {
    if (req && req.ip) {
      const ip = clean(req.ip);
      if (ip) return ip;
    }
    if (req && req.connection && req.connection.remoteAddress) {
      const ip = clean(req.connection.remoteAddress);
      if (ip) return ip;
    }
  } catch (_) {}
  return "?";
}
function rawXffChain(req) {
  // Teshis alani: guvenilmez ham zincir (spoof edilebilir, karar icin DEGIL gozlem icin)
  try {
    const raw = req && (req.headers["x-forwarded-for"] || req.headers["X-Forwarded-For"]);
    const s = String(raw || "").trim().slice(0, 200);
    return s || "-";
  } catch (_) { return "-"; }
}
function makeLog(action, user, detail, req) {
  return {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    action,
    user,
    detail,
    ip: req ? clientIp(req) : "?",
    xff: req ? rawXffChain(req) : "-",
  };
}

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla istek. Lütfen bekleyin." },
});
app.use(generalLimiter);

const otpSendLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla OTP isteği. Lütfen bekleyin." },
});

const otpVerifyLimiter = rateLimit({
  windowMs: 3 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla doğrulama denemesi. Lütfen bekleyin." },
});

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendOtpEmail(email, otp) {
  const otpChars = otp.split("").map((ch) =>
    `<td style="width:48px;height:56px;border:2px solid #2563eb;border-radius:8px;text-align:center;font-size:28px;font-weight:bold;color:#2563eb;background:#fff;font-family:monospace;">${ch}</td>`
  ).join("");
  await transporter.sendMail({
    from: `"OTP Girişi" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "OTP Doğrulama Kodu",
    html: `
      <div style="font-family: Arial; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
        <h2 style="color: #333;">OTP Doğrulama Kodu</h2>
        <p>Aşağıdaki kodu kullanarak sisteme giriş yapabilirsiniz:</p>
        <table style="margin:20px auto;border-collapse:separate;border-spacing:8px;">
          <tr>${otpChars}</tr>
        </table>
        <p style="color: #666;">Bu kod yalnızca 3 dakika geçerlidir.</p>
        <hr style="border: none; border-top: 1px solid #eee;" />
        <p style="color: #999; font-size: 12px;">Bu mesajı siz talep etmediyseniz dikkate almayın.</p>
      </div>
    `,
  });
}

function generateOtp() {
  return crypto.randomInt(100000, 999999).toString();
}

function detectRole(email) {
  const e = email.toLowerCase();
  if (e.includes("lise")) return "lise";
  if (e.includes("ortaokul")) return "ortaokul";
  return "diger";
}

function buildProfileStats(users, email) {
  const profile = users && users[email] ? users[email].profile : null;
  if (profile && (profile.studentCount || profile.teacherCount || profile.classCount)) {
    return [
      { label: "Öğrenci Sayısı", value: profile.studentCount || "0", icon: "fa-user-graduate", color: "#6366f1" },
      { label: "Öğretmen", value: profile.teacherCount || "0", icon: "fa-chalkboard-user", color: "#22c55e" },
      { label: "Şube", value: profile.classCount || "0", icon: "fa-door-open", color: "#f59e0b" },
    ];
  }
  return [
    { label: "Öğrenci Sayısı", value: "-", icon: "fa-user-graduate", color: "#6366f1" },
    { label: "Öğretmen", value: "-", icon: "fa-chalkboard-user", color: "#22c55e" },
    { label: "Şube", value: "-", icon: "fa-door-open", color: "#f59e0b" },
  ];
}

function getDashboardData(role, users, email) {
  const userList = users ? Object.values(users) : [];
  const totalUsers = userList.length;
  const liseCount = userList.filter((u) => u.role === "lise").length;
  const ortaokulCount = userList.filter((u) => u.role === "ortaokul").length;
  const adminCount = userList.filter((u) => u.role === "admin").length;
  const digerCount = userList.filter((u) => u.role === "diger").length;

  const allAnn = loadAnnouncements();
  const now = Date.now();
  const activeAnn = allAnn.filter((a) => a.expiresAt > now);
  const filteredAnn = activeAnn.filter(
    (a) => a.target === "all" || groupTargetMatches(a.target, role, getUserOwnership(users, email))
  ).map((a) => ({
    id: a.id,
    title: a.title,
    content: a.content,
    target: a.target,
    createdAt: a.createdAt,
    expiresAt: a.expiresAt,
    readBy: a.readBy || [],
    read: (a.readBy || []).includes(email),
  }));

  const openRequestCount = loadRequests().filter((r) => r.status === "open").length;
  const activeAnnCount = activeAnn.length;
  const activeFileCount = loadFiles().filter((f) => (f.startsAt || 0) <= now && f.expiresAt > now).length;

  const roleData = {
    admin: {
      announcements: filteredAnn,
      links: [
        { title: "Kullanıcı Yönetimi", url: "/navigate/users", icon: "fa-users-gear", desc: "Kullanıcı rollerini yönetin" },
        { title: "Duyuru Panosu", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler", badge: activeAnnCount },
        { title: "Dosya Yönetimi", url: "/navigate/files", icon: "fa-folder", desc: "Belge ve dosya paylaşımı", badge: activeFileCount },
        { title: "Anketler", url: "/navigate/surveys", icon: "fa-square-poll-vertical", desc: "Anketleri oluşturun ve sonuçları görüntüleyin" },
        { title: "Talep/İtiraz", url: "/navigate/requests", icon: "fa-paper-plane", desc: "Okullardan gelen talepler", badge: openRequestCount },
        { title: "Log Kayıtları", url: "/navigate/logs", icon: "fa-clipboard-list", desc: "Sistem hareketlerini inceleyin" },
        { title: "Raporlar", url: "/navigate/reports", icon: "fa-chart-bar", desc: "İstatistik ve grafik raporları" },
        { title: "Sistem Ayarları", url: "/navigate/settings", icon: "fa-sliders", desc: "Genel sistem yapılandırması" },
      ],
      stats: [
        { label: "Toplam Kullanıcı", value: String(totalUsers), icon: "fa-users", color: "#6366f1" },
        { label: "Aktif (5 dk)", value: String(countPresence(5)), icon: "fa-signal", color: "#10b981" },
        { label: "Yöneticiler", value: String(adminCount), icon: "fa-user-gear", color: "#22c55e" },
        { label: "Lise Grubu", value: String(liseCount), icon: "fa-school", color: "#f59e0b" },
        { label: "Ortaokul Grubu", value: String(ortaokulCount), icon: "fa-school", color: "#a855f7" },
        { label: "Diğer Grubu", value: String(digerCount), icon: "fa-users", color: "#ec4899" },
      ],
    },
    lise: {
      announcements: filteredAnn,
      stats: buildProfileStats(users, email),
      links: [
        { title: "Duyurular", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler" },
        { title: "Anketler", url: "/navigate/surveys", icon: "fa-square-poll-vertical", desc: "Anketleri görüntüleyin ve yanıtlayın" },
        { title: "Dosya Dağıtım", url: "/navigate/files", icon: "fa-folder-open", desc: "Dağıtılan dosyaları indirin" },
        { title: "Belge İstekleri", url: "/navigate/file-requests", icon: "fa-file-arrow-up", desc: "İstenen belgeleri yükleyin" },
      ],
    },
    ortaokul: {
      announcements: filteredAnn,
      stats: buildProfileStats(users, email),
      links: [
        { title: "Duyurular", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler" },
        { title: "Anketler", url: "/navigate/surveys", icon: "fa-square-poll-vertical", desc: "Anketleri görüntüleyin ve yanıtlayın" },
        { title: "Dosya Dağıtım", url: "/navigate/files", icon: "fa-folder-open", desc: "Dağıtılan dosyaları indirin" },
        { title: "Belge İstekleri", url: "/navigate/file-requests", icon: "fa-file-arrow-up", desc: "İstenen belgeleri yükleyin" },
      ],
    },
    diger: {
      announcements: filteredAnn,
      stats: buildProfileStats(users, email),
      links: [
        { title: "Duyurular", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler" },
        { title: "Anketler", url: "/navigate/surveys", icon: "fa-square-poll-vertical", desc: "Anketleri görüntüleyin ve yanıtlayın" },
        { title: "Dosya Dağıtım", url: "/navigate/files", icon: "fa-folder-open", desc: "Dağıtılan dosyaları indirin" },
        { title: "Belge İstekleri", url: "/navigate/file-requests", icon: "fa-file-arrow-up", desc: "İstenen belgeleri yükleyin" },
      ],
    },
  };

  if (role !== "admin" && roleData[role]) {
    const unreadAnn = filteredAnn.filter((a) => !a.read).length;

    const allSurveyList = loadSurveys();
    const activeSurveys = allSurveyList.filter((s) => s.expiresAt > now);
    const targetedSurveys = activeSurveys.filter((s) => isSurveyTargeted(s, email, role, getUserOwnership(users, email)));
    const allResp = loadResponses();
    const userResp = allResp.filter((r) => r.userId === email);
    const unansweredSurveys = targetedSurveys.filter((s) => !userResp.some((r) => r.surveyId === s.id)).length;

    const allFileList = loadFiles();
    const targetedFiles = allFileList.filter((f) => (f.startsAt || 0) <= now && f.expiresAt > now && isFileTargeted(f, email, role, getUserOwnership(users, email)));
    const undownloadedFiles = targetedFiles.filter((f) => !(f.downloads || []).some((d) => d.userId === email)).length;

    const allFr = loadFileRequests();
    const activeFr = allFr.filter((fr) => fr.expiresAt > now && isFrTargeted(fr, email, role, getUserOwnership(users, email)));
    const pendingFr = activeFr.filter((fr) => !(fr.submissions || []).some((s) => s.userEmail === email)).length;

    if (roleData[role] && roleData[role].links) {
      roleData[role].links[0].badge = unreadAnn;
      roleData[role].links[1].badge = unansweredSurveys;
      roleData[role].links[2].badge = undownloadedFiles;
      const frLink = roleData[role].links[3];
      if (pendingFr > 0) {
        frLink.badge = pendingFr;
        frLink.highlight = true;
      } else {
        roleData[role].links.splice(3, 1);
      }
    }
  }

  return roleData[role] || roleData.admin;
}

app.get("/api/captcha", (req, res) => {
  const code = crypto.randomInt(10000, 99999).toString();
  const id = crypto.randomUUID();
  const svg = generateCaptchaSvg(code);
  captchaStore.set(id, { answer: code, createdAt: Date.now() });
  res.json({ id, svg });
});

function cleanupUploadedFiles(req) {
  if (!Array.isArray(req.files)) return;
  for (const f of req.files) {
    try { if (f && f.path) fs.unlinkSync(f.path); } catch (_) {}
  }
}

function contentDisposition(name, type = "attachment") {
  const safe = String(name || "dosya").replace(/[\r\n"\\]/g, "_");
  return `${type}; filename="${safe}"`;
}

// CSV formül enjeksiyon koruması: = + - @ tab CR ile başlayan hücreleri metne zorla
function csvCell(v) {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
}

app.post("/api/send-otp", otpSendLimiter, async (req, res) => {
  try {
    const { email, captchaId, captcha } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Gecerli bir e-posta adresi girin." });
    }
    // MEB typo kontrolü: meb.k12.tr'ye benzeyip tam eşleşmeyen domaini erken reddet
    // (admin gibi farklı domainlere izin verilir, sadece bariz typo engellenir)
    {
      const norm = String(email).toLowerCase().trim();
      const at = norm.lastIndexOf("@");
      const domain = at > 0 ? norm.slice(at + 1) : "";
      const flat = domain.replace(/[^a-z0-9]/g, "");
      const looksLikeMeb = domain !== "meb.k12.tr" && (
        flat === "mebk12tr" ||
        domain.includes("meb") ||
        domain.includes("k12") ||
        domain.includes("k.12")
      );
      if (looksLikeMeb) {
        return res.status(400).json({ error: "E-posta adresi geçerli değil." });
      }
    }
    if (!captchaId || !captcha) {
      return res.status(400).json({ error: "Guvenlik kodu gerekli." });
    }

    const stored = captchaStore.get(captchaId);
    if (!stored) {
      return res.status(400).json({ error: "Guvenlik kodunun süresi dolmus. Yeniden yükleyin.", captchaExpired: true });
    }
    if (stored.answer !== captcha.trim()) {
      captchaStore.delete(captchaId);
      return res.status(400).json({ error: "Guvenlik kodu yanlis.", captchaExpired: true });
    }
    captchaStore.delete(captchaId);

    const normEmail = email.toLowerCase().trim();
    const now = Date.now();

    const registered = loadUsers();
    if (!registered[normEmail]) {
      // Güvenlik: kayıtsız e-postalarda da aynı yanıt + cooldown uygulanır (kullanıcı sayımı engeli)
      lastOtpRequest.set(normEmail, Date.now());
      return res.json({
        message: "OTP kodu e-posta adresinize gönderildi.",
        expiresIn: OTP_EXPIRY_MS,
      });
    }

    const lastReq = lastOtpRequest.get(normEmail);
    if (lastReq && now - lastReq < OTP_COOLDOWN_MS) {
      const remaining = Math.ceil((OTP_COOLDOWN_MS - (now - lastReq)) / 1000);
      return res.status(429).json({
        error: `Yeni kod istemek icin ${remaining} saniye bekleyin.`,
        cooldown: remaining,
      });
    }

    const otp = generateOtp();
    await sendOtpEmail(normEmail, otp);
    otpStore.set(normEmail, { otp, expires: Date.now() + OTP_EXPIRY_MS, sentAt: Date.now() });
    lastOtpRequest.set(normEmail, Date.now());
    appendLog(makeLog("otp_request", normEmail, `${normEmail} adresine OTP gönderildi.`, req));
    res.json({
      message: "OTP kodu e-posta adresinize gönderildi.",
      expiresIn: OTP_EXPIRY_MS,
    });
  } catch (err) {
    console.error("E-posta gonderilemedi:", err.message);
    res.status(500).json({ error: "E-posta gönderilemedi. SMTP ayarlarını kontrol edin." });
  }
});

app.post("/api/verify-otp", otpVerifyLimiter, (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: "E-posta ve OTP kodu gerekli." });
  }

  const normEmail = email.toLowerCase().trim();
  const now = Date.now();

  const failData = failedAttempts.get(normEmail);
  if (failData && failData.count >= MAX_FAILED_ATTEMPTS) {
    const lockBase = failData.lastAttempt || failData.firstAttempt;
    if (now - lockBase < LOCKOUT_DURATION_MS) {
      const remaining = Math.ceil((LOCKOUT_DURATION_MS - (now - lockBase)) / 1000);
      return res.status(429).json({
        error: `Çok fazla başarısız deneme. ${remaining} saniye bekleyin.`,
        lockout: remaining,
      });
    }
    failedAttempts.delete(normEmail);
  }

  const record = otpStore.get(normEmail);
  if (!record) {
    return res.status(400).json({ error: "Önce OTP kodu isteyin." });
  }
  if (now > record.expires) {
    otpStore.delete(normEmail);
    return res.status(400).json({ error: "OTP kodunun süresi doldu. Yeni kod isteyin." });
  }
  if (String(record.otp) !== String(otp)) {
    const current = failedAttempts.get(normEmail);
    if (!current) {
      failedAttempts.set(normEmail, { count: 1, firstAttempt: now, lastAttempt: now });
    } else {
      current.count += 1;
      current.lastAttempt = now;
    }
    return res.status(400).json({ error: "Geçersiz OTP kodu." });
  }

  otpStore.delete(normEmail);
  failedAttempts.delete(normEmail);

  const users = loadUsers();
  if (!users[normEmail]) {
    return res.status(403).json({ error: "Bu e-posta adresi sistemde kayıtlı değil." });
  }

  users[normEmail].lastLogin = now;
  if (!users[normEmail].role) {
    users[normEmail].role = detectRole(normEmail);
  }
  saveUsers(users);

  const tokenExpiry = users[normEmail].role === "admin" ? "1h" : "30m";
  const tokenPayload = { email: normEmail, role: users[normEmail].role };
  if (users[normEmail].crossRoles && users[normEmail].crossRoles.length > 0) {
    tokenPayload.crossRoles = users[normEmail].crossRoles;
  }
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: tokenExpiry });
  appendLog(makeLog("login", normEmail, `${normEmail} basariyla giris yapti.`, req));
  res.json({ token, email: normEmail, role: users[normEmail].role, crossRoles: users[normEmail].crossRoles || [] });
});

app.get("/api/me", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token gerekli." });
  }
  try {
    const decoded = jwt.verify(auth.split(" ")[1], JWT_SECRET);
    res.json({ email: decoded.email });
  } catch (_) {
    res.status(401).json({ error: "Geçersiz veya süresi dolmuş token." });
  }
});

app.get("/api/profile", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });
  res.json({
    email: user.email,
    role: user.role,
    crossRoles: user.crossRoles || [],
    profile: user.profile || null,
    created: user.created,
    lastLogin: user.lastLogin,
  });
});

app.put("/api/profile", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  if (!users[decoded.email]) {
    return res.status(403).json({ error: "Kullanıcı bulunamadı." });
  }

  const { schoolName, schoolCode, city, district, principalName, principalPhone, schoolPhone, studentCount, teacherCount, classCount } = req.body;
  const autoCode = decoded.email.split("@")[0];
  const prevProfile = users[decoded.email].profile || {};
  users[decoded.email].profile = {
    ...prevProfile,
    schoolName: schoolName || "",
    schoolCode: schoolCode || autoCode,
    city: city || "",
    district: district || "",
    principalName: principalName || "",
    principalPhone: principalPhone || "",
    schoolPhone: schoolPhone || "",
    studentCount: studentCount || "",
    teacherCount: teacherCount || "",
    classCount: classCount || "",
  };
  saveUsers(users);
  appendLog(makeLog("profile_update", decoded.email, "Okul bilgileri güncellendi.", req));
  res.json(users[decoded.email].profile);
});

app.get("/api/dashboard", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token gerekli." });
  }
  try {
    const decoded = jwt.verify(auth.split(" ")[1], JWT_SECRET);
    const users = loadUsers();
    const user = users[decoded.email];
    if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });
    const activeRole = resolveRole(user, req);
    const data = getDashboardData(activeRole, users, decoded.email);
    res.json({ role: activeRole, ...data });
  } catch (_) {
    res.status(401).json({ error: "Geçersiz veya süresi dolmuş token." });
  }
});

function authUser(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return null;
  try {
    return jwt.verify(auth.split(" ")[1], JWT_SECRET);
  } catch { return null; }
}

function resolveRole(user, req) {
  const asRole = req.query && req.query.asRole;
  if (asRole) {
    const available = [user.role, ...(user.crossRoles || [])];
    if (available.includes(asRole)) return asRole;
  }
  return user.role;
}

function requireAdmin(req, res) {
  const decoded = authUser(req);
  if (!decoded) {
    res.status(401).json({ error: "Token gerekli." });
    return null;
  }
  const users = loadUsers();
  const user = users[decoded.email];
  if (!user || user.role !== "admin") {
    res.status(403).json({ error: "Bu işlem için admin yetkisi gerekli." });
    return null;
  }
  return decoded;
}

app.get("/api/users", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const users = loadUsers();
  const list = Object.entries(users).map(([email, data]) => ({
    email,
    role: data.role || "diger",
    crossRoles: data.crossRoles || [],
    profile: data.profile || null,
    created: data.created,
    lastLogin: data.lastLogin,
  }));
  res.json(list);
});

// ---- Presence (aktif kullanicilar, admin) ----
app.get("/api/presence", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const minutes = Math.min(120, Math.max(1, Number(req.query.minutes) || 5));
  const cutoff = Date.now() - minutes * 60 * 1000;
  const map = loadPresence();
  const users = loadUsers();
  const list = Object.entries(map)
    .filter(([, ts]) => ts >= cutoff)
    .map(([email, ts]) => ({
      email,
      role: users[email]?.role || "?",
      schoolName: users[email]?.profile?.schoolName || "",
      district: users[email]?.profile?.district || "",
      lastSeen: ts,
    }))
    .sort((a, b) => b.lastSeen - a.lastSeen);
  res.json({ windowMinutes: minutes, active: list.length, users: list });
});

app.get("/api/users/:email", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const normEmail = decodeURIComponent(req.params.email).toLowerCase().trim();
  const users = loadUsers();
  const user = users[normEmail];
  if (!user) return res.status(404).json({ error: "Kullanıcı bulunamadı." });
  res.json(user);
});

app.post("/api/users", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const { email, role, ownership } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Geçerli bir e-posta adresi girin." });
  }
  const validRoles = ["admin", "lise", "ortaokul", "diger"];
  const userRole = validRoles.includes(role) ? role : detectRole(email);
  const normOwn = detectOwnership(ownership);
  if (userRole !== "admin" && !normOwn) {
    return res.status(400).json({ error: "Okul türü gerekli (resmi / ozel)." });
  }

  const normEmail = email.toLowerCase().trim();
  const users = loadUsers();
  if (users[normEmail]) {
    return res.status(409).json({ error: "Bu e-posta adresi zaten kayıtlı." });
  }

  const schoolMatch = normEmail.match(/^(\d+)@meb\.(gov\.tr|k12\.tr)$/);
  const profile = schoolMatch ? { schoolCode: schoolMatch[1] } : {};
  if (normOwn) profile.ownership = normOwn;
  users[normEmail] = {
    email: normEmail,
    role: userRole,
    created: Date.now(),
    lastLogin: null,
    profile: Object.keys(profile).length ? profile : undefined,
  };
  saveUsers(users);
  appendLog(makeLog("user_create", decoded.email, `${normEmail} (${userRole}) kullanıcı eklendi.`, req));
  res.status(201).json(users[normEmail]);
});

app.put("/api/users/:email", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const normEmail = decodeURIComponent(req.params.email).toLowerCase().trim();
  const users = loadUsers();
  if (!users[normEmail]) {
    return res.status(404).json({ error: "Kullanıcı bulunamadı." });
  }

  const { role, crossRoles, ownership } = req.body;
  const validRoles = ["admin", "lise", "ortaokul", "diger"];
  const currentRole = role && validRoles.includes(role) ? role : users[normEmail].role;
  if (role && validRoles.includes(role) && role !== users[normEmail].role) {
    const oldRole = users[normEmail].role;
    users[normEmail].role = role;
    appendLog(makeLog("user_role_change", decoded.email, `${normEmail}: ${oldRole} -> ${role}`, req));
  }
  if (ownership !== undefined) {
    const normOwn = detectOwnership(ownership);
    const oldOwn = (users[normEmail].profile || {}).ownership || "";
    if (normOwn !== oldOwn) {
      users[normEmail].profile = { ...(users[normEmail].profile || {}), ownership: normOwn };
      appendLog(makeLog("user_ownership_change", decoded.email, `${normEmail}: ${oldOwn || "-"} -> ${normOwn || "-"}`, req));
    }
  }
  if (crossRoles !== undefined) {
    const crossList = Array.isArray(crossRoles) ? crossRoles : [];
    const validCross = crossList.filter((r) => validRoles.includes(r) && r !== currentRole);
    users[normEmail].crossRoles = validCross;
  }
  saveUsers(users);
  res.json(users[normEmail]);
});

app.delete("/api/users/clear", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const users = loadUsers();
  let deleted = 0;
  for (const [email, u] of Object.entries(users)) {
    if (u.role !== "admin") {
      delete users[email];
      deleted++;
    }
  }
  saveUsers(users);
  appendLog(makeLog("user_delete", decoded.email, `${deleted} kullanıcı silindi (admin haric).`, req));
  res.json({ deleted });
});

app.delete("/api/users/by-role/:role", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const { role } = req.params;
  if (role === "admin") {
    return res.status(400).json({ error: "Admin grubu silinemez." });
  }
  const validRoles = ["lise", "ortaokul", "diger"];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ error: "Geçersiz rol: " + role });
  }

  const users = loadUsers();
  let deleted = 0;
  for (const [email, u] of Object.entries(users)) {
    if (u.role === role) {
      delete users[email];
      deleted++;
    }
  }
  saveUsers(users);
  appendLog(makeLog("user_delete", decoded.email, deleted + " kullanıcı silindi (" + role + ").", req));
  res.json({ deleted, role });
});

app.delete("/api/users/:email", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const normEmail = decodeURIComponent(req.params.email).toLowerCase().trim();
  const users = loadUsers();
  if (!users[normEmail]) {
    return res.status(404).json({ error: "Kullanıcı bulunamadı." });
  }
  if (normEmail === decoded.email) {
    return res.status(400).json({ error: "Kendinizi silemezsiniz." });
  }

  const deleted = users[normEmail];
  delete users[normEmail];
  saveUsers(users);
  appendLog(makeLog("user_delete", decoded.email, `${normEmail} (${deleted.role}) kullanıcı silindi.`, req));
  res.json({ message: "Kullanıcı silindi." });
});

function detectOwnership(val) {
  const v = String(val || "").toLowerCase().replace(/ü/g, "u").replace(/ğ/g, "g").replace(/ı/g, "i").replace(/ş/g, "s").replace(/ö/g, "o").replace(/ç/g, "c").trim();
  if (v.includes("ozel")) return "ozel";
  if (v.includes("resmi")) return "resmi";
  return "";
}

// Grup hedefleme: rol (lise/ortaokul/diger) veya ownership (resmi/ozel).
// "resmi" secimi tum resmi okullara (lise+ortaokul+diger) gider, rolden bagimsizdir.
const OWNERSHIP_GROUPS = ["resmi", "ozel"];
function getUserOwnership(users, email) {
  return ((users || {})[email]?.profile?.ownership) || "";
}
function groupTargetMatches(targetGroup, userRole, userOwnership) {
  if (!targetGroup) return false;
  if (targetGroup === userRole) return true;
  if (OWNERSHIP_GROUPS.includes(targetGroup) && userOwnership === targetGroup) return true;
  return false;
}
// Coklu grup hedefleme: eski tekil alanlar (targetGroup/target) aynen calismaya
// devam eder; yeni targetGroups/targets dizisi VEYA mantigiyla eslesir.
const VALID_GROUPS = ["lise", "ortaokul", "diger", "resmi", "ozel"];
function sanitizeTargetGroups(v) {
  let arr = v;
  if (typeof v === "string" && v) {
    try {
      const parsed = JSON.parse(v);
      arr = Array.isArray(parsed) ? parsed : v.split(",");
    } catch (_) {
      arr = v.split(",");
    }
  }
  if (!Array.isArray(arr)) arr = [];
  const out = [];
  for (const g of arr) {
    const t = String(g || "").trim();
    if (VALID_GROUPS.includes(t) && !out.includes(t)) out.push(t);
  }
  return out;
}
function matchedGroups(item) {
  const out = [];
  const push = (g) => {
    const t = String(g || "").trim();
    if (VALID_GROUPS.includes(t) && !out.includes(t)) out.push(t);
  };
  push(item.targetGroup);
  push(item.target);
  sanitizeTargetGroups(item.targetGroups || item.targets).forEach(push);
  return out;
}
function isGroupTargeted(item, userRole, userOwnership) {
  // Yeni model (tur x rol kesisimi): targetOwnership varsa VE mantigi kullanilir.
  // Kayitta bu alan yoksa eski VEYA modeline dusulur (geriye uyumluluk).
  if (item && item.targetOwnership !== undefined) {
    const own = item.targetOwnership || "all";
    const roles = Array.isArray(item.targetRoles) ? item.targetRoles.filter((r) => ["lise", "ortaokul", "diger"].includes(r)) : [];
    const ownOk = own === "all" || userOwnership === own;
    const roleOk = roles.length === 0 || roles.includes(userRole);
    return ownOk && roleOk;
  }
  return matchedGroups(item).some((g) => groupTargetMatches(g, userRole, userOwnership));
}
function countGroupTargets(userList, targetGroup) {
  return (userList || []).filter(
    (u) => u.role !== "admin" && groupTargetMatches(targetGroup, u.role, (u.profile || {}).ownership || "")
  ).length;
}
function countItemTargets(userList, item) {
  return (userList || []).filter(
    (u) => u.role !== "admin" && isGroupTargeted(item, u.role, (u.profile || {}).ownership || "")
  ).length;
}
const VALID_ROLES = ["lise", "ortaokul", "diger"];
function sanitizeTargetRoles(v) {
  let arr = v;
  if (typeof v === "string" && v) {
    try {
      const parsed = JSON.parse(v);
      arr = Array.isArray(parsed) ? parsed : v.split(",");
    } catch (_) {
      arr = v.split(",");
    }
  }
  if (!Array.isArray(arr)) arr = [];
  const out = [];
  for (const r of arr) {
    const t = String(r || "").trim();
    if (VALID_ROLES.includes(t) && !out.includes(t)) out.push(t);
  }
  return out;
}
// Tur x rol secimi: {ownership, roles} yenidir (VE mantigi).
// Eski istemciden sadece targetGroup/targetGroups gelirse ve karsiligi
// yeni modelde ifade edilebiliyorsa donustur, yoksa legacy birak (null).
function resolveTargetSelection(targetType, src) {
  const out = { group: null, groups: [], ownership: null, roles: null };
  if (targetType !== "group") return out;
  const hasNew = src && (src.targetOwnership !== undefined || src.targetRoles !== undefined);
  if (hasNew) {
    const ownership = ["resmi", "ozel"].includes(src.targetOwnership) ? src.targetOwnership : "all";
    const roles = sanitizeTargetRoles(src.targetRoles);
    out.ownership = ownership;
    out.roles = roles;
    if (ownership !== "all" && roles.length === 0) {
      out.groups = [ownership]; out.group = ownership;
    } else if (ownership === "all" && roles.length > 0) {
      out.groups = [...roles]; out.group = roles[0];
    } else if (ownership !== "all" && roles.length > 0) {
      out.groups = [...roles, ownership]; out.group = roles[0];
    }
    return out;
  }
  const legacy = resolveTargetGroups(targetType, src.targetGroup, src.targetGroups);
  out.group = legacy.group; out.groups = legacy.groups;
  const rolePart = legacy.groups.filter((g) => VALID_ROLES.includes(g));
  const ownPart = legacy.groups.filter((g) => OWNERSHIP_GROUPS.includes(g));
  if (legacy.groups.length > 0 && ownPart.length === 0) {
    out.ownership = "all"; out.roles = rolePart;
  } else if (legacy.groups.length === 1 && ownPart.length === 1) {
    out.ownership = ownPart[0]; out.roles = [];
  }
  return out;
}
// Hedef cozumleme: tekil targetGroup geriye uyumluluk icin korunur,
// coklu secim targetGroups dizisinde tutulur (bos dizi = secim yok).
function resolveTargetGroups(targetType, targetGroup, targetGroups) {
  if (targetType !== "group") return { group: null, groups: [] };
  const groups = sanitizeTargetGroups(targetGroups);
  if (groups.length === 0 && VALID_GROUPS.includes(String(targetGroup || "").trim())) {
    groups.push(String(targetGroup).trim());
  }
  return { group: groups[0] || null, groups };
}

app.post("/api/users/import", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const XLSX = require("xlsx");
  const importUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });
  importUpload.single("file")(req, res, (err) => {
    if (err) return res.status(400).json({ error: "Dosya yüklenirken hata: " + err.message });
    if (!req.file) return res.status(400).json({ error: "Dosya secilmedi." });

    try {
      const wb = XLSX.read(req.file.buffer, { type: "buffer" });
      const ws = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(ws, { defval: "" });
      if (rows.length === 0) return res.status(400).json({ error: "Excel dosyasi bos." });

      const users = loadUsers();
      let added = 0, updated = 0, skipped = 0, errors = [];
      const colMap = { il: null, ilce: null, genelMudurluk: null, kurumTuru: null, kurumKodu: null, kurum: null, resmiOzel: null };
      function normalizeCol(s) {
        return s.replace(/İ/g, "i").toLowerCase().replace(/[\s\-_]/g, "").replace(/ü/g, "u").replace(/ğ/g, "g").replace(/ı/g, "i").replace(/ş/g, "s").replace(/ö/g, "o").replace(/ç/g, "c");
      }
      const firstRow = rows[0];
      for (const key of Object.keys(firstRow)) {
        const k = normalizeCol(key);
        if (k.includes("ilce")) colMap.ilce = key;
        else if (k === "il") colMap.il = key;
        else if (k.includes("resmi") || k.includes("ozel") || k.includes("mulkiyet")) colMap.resmiOzel = key;
        else if (k.includes("genel") || k.includes("mudurluk")) colMap.genelMudurluk = key;
        else if (k.includes("tur") || k.includes("turu")) colMap.kurumTuru = key;
        else if (k.includes("kod") || k.includes("kodu")) colMap.kurumKodu = key;
        else if (k === "kurum" || k.includes("kurumad") || k.includes("adi")) colMap.kurum = key;
      }
      if (!colMap.kurumKodu) {
        return res.status(400).json({ error: "Excel'de 'Kurum Kodu' sutunu bulunamadı." });
      }

      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const kurumKodu = String(row[colMap.kurumKodu]).trim();
        if (!kurumKodu) { skipped++; continue; }
        const email = kurumKodu.toLowerCase() + "@meb.k12.tr";
        const rawKurumTuru = colMap.kurumTuru ? String(row[colMap.kurumTuru] || "").trim() : "";
        const kurumTuruCheck = rawKurumTuru.toLowerCase().replace(/ü/g, "u").replace(/ğ/g, "g").replace(/ı/g, "i").replace(/ş/g, "s").replace(/ö/g, "o").replace(/ç/g, "c");
        const rawKurumAdi = colMap.kurum ? String(row[colMap.kurum] || "").trim() : "";
        const kurumAdiCheck = rawKurumAdi.toLowerCase().replace(/ü/g, "u").replace(/ğ/g, "g").replace(/ı/g, "i").replace(/ş/g, "s").replace(/ö/g, "o").replace(/ç/g, "c");

        let role = "diger";
        const checkStr = kurumTuruCheck || kurumAdiCheck;
        if (checkStr.includes("ortaokul")) {
          role = "ortaokul";
        } else if (checkStr.includes("lisesi") || checkStr.includes("lise") || checkStr.includes("meslek")) {
          role = "lise";
        } else if (["ilkokulu", "ilkokul", "merkezi", "kademe", "anaokul", "anaokulu"].some(k => checkStr.includes(k))) {
          role = "diger";
        } else if (email.includes("ortaokul")) {
          role = "ortaokul";
        } else if (email.includes("lise")) {
          role = "lise";
        }

        const profile = {
          schoolName: rawKurumAdi,
          city: colMap.il ? String(row[colMap.il] || "").trim() : "",
          district: colMap.ilce ? String(row[colMap.ilce] || "").trim() : "",
          schoolCode: kurumKodu,
          institutionType: rawKurumTuru,
          directorate: colMap.genelMudurluk ? String(row[colMap.genelMudurluk] || "").trim() : "",
          ownership: detectOwnership(colMap.resmiOzel ? String(row[colMap.resmiOzel] || "").trim() : ""),
        };
        if (users[email]) {
          users[email].profile = { ...(users[email].profile || {}), ...profile };
          users[email].role = role;
          updated++;
        } else {
          users[email] = { email, role, created: Date.now(), lastLogin: null, profile };
          added++;
        }
      }
      saveUsers(users);
      appendLog(makeLog("user_import", decoded.email, `${added} yeni, ${updated} güncellendi.`, req));
      res.json({ added, updated, skipped, errors: errors.length > 0 ? errors.slice(0, 10) : [] });
    } catch (e) {
      res.status(400).json({ error: "Excel okunurken hata: " + e.message });
    }
  });
});

// ---- Announcements ----

app.get("/api/announcements", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const activeRole = resolveRole(user, req);

  const allAnn = loadAnnouncements();
  const now = Date.now();

  let list;
  if (user.role === "admin") {
    list = allAnn.map((a) => ({
      ...a,
      readBy: a.readBy || [],
      readCount: (a.readBy || []).length,
    }));
  } else {
    list = allAnn
      .filter((a) => a.expiresAt > now && (a.target === "all" || isGroupTargeted(a, activeRole, getUserOwnership(users, decoded.email))))
      .map((a) => ({
        id: a.id,
        title: a.title,
        content: a.content,
        target: a.target,
        createdAt: a.createdAt,
        expiresAt: a.expiresAt,
        read: (a.readBy || []).includes(decoded.email),
      }));
  }

  res.json(list);
});

app.post("/api/announcements", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const { title, content, target, targetGroups, targetOwnership, targetRoles, expiresInDays } = req.body;
  if (!title || !content) {
    return res.status(400).json({ error: "Başlık ve içerik gerekli." });
  }
  if (String(title).length > 200 || String(content).length > 5000) {
    return res.status(400).json({ error: "Başlık en fazla 200, içerik en fazla 5000 karakter olabilir." });
  }
  const validTargets = ["all", "lise", "ortaokul", "diger", "resmi", "ozel"];
  const isAll = target === "all" && sanitizeTargetGroups(targetGroups).length === 0 && targetOwnership === undefined && targetRoles === undefined;
  const annTg = isAll
    ? { group: null, groups: [], ownership: null, roles: null }
    : resolveTargetSelection("group", { targetGroup: target === "all" ? null : target, targetGroups, targetOwnership, targetRoles });
  if (!isAll && annTg.groups.length === 0 && annTg.ownership === null) {
    if (!validTargets.includes(target)) return res.status(400).json({ error: "Geçersiz hedef kitle." });
    annTg.group = target; annTg.groups = [target];
  }

  const list = loadAnnouncements();
  const ann = {
    id: crypto.randomUUID(),
    title,
    content,
    target: isAll ? "all" : (annTg.group || target),
    targets: sanitizeTargetGroups(targetGroups),
    targetOwnership: annTg.ownership,
    targetRoles: annTg.roles,
    createdBy: decoded.email,
    createdAt: Date.now(),
    expiresAt: Date.now() + (expiresInDays || 7) * 24 * 60 * 60 * 1000,
    readBy: [],
  };
  list.push(ann);
  saveAnnouncements(list);
  appendLog(makeLog("announcement_create", decoded.email, `"${title}" duyurusu oluşturuldu (hedef: ${ann.target}).`, req));
  res.status(201).json(ann);
});

app.put("/api/announcements/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const list = loadAnnouncements();
  const idx = list.findIndex((a) => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Duyuru bulunamadı." });

  const { title, content, target, targetGroups, targetOwnership, targetRoles, expiresInDays } = req.body;
  if (title && String(title).length > 200) {
    return res.status(400).json({ error: "Başlık en fazla 200 karakter olabilir." });
  }
  if (content && String(content).length > 5000) {
    return res.status(400).json({ error: "İçerik en fazla 5000 karakter olabilir." });
  }
  if (title) list[idx].title = title;
  if (content) list[idx].content = content;
  if (target !== undefined || targetGroups !== undefined || targetOwnership !== undefined || targetRoles !== undefined) {
    if (target === "all") {
      list[idx].target = "all";
      list[idx].targets = [];
      list[idx].targetOwnership = null;
      list[idx].targetRoles = null;
    } else {
      const annTg = resolveTargetSelection("group", { targetGroup: target, targetGroups, targetOwnership, targetRoles });
      const hasSel = (annTg.groups || []).length > 0 || annTg.ownership !== null;
      if (hasSel) {
        list[idx].target = annTg.group;
        list[idx].targets = annTg.groups;
        list[idx].targetOwnership = annTg.ownership;
        list[idx].targetRoles = annTg.roles;
      } else if (target) {
        const validTargets = ["all", "lise", "ortaokul", "diger", "resmi", "ozel"];
        if (validTargets.includes(target)) list[idx].target = target;
      }
    }
  }
  if (expiresInDays) {
    list[idx].expiresAt = Date.now() + expiresInDays * 24 * 60 * 60 * 1000;
  }
  saveAnnouncements(list);
  appendLog(makeLog("announcement_edit", decoded.email, `"${list[idx].title}" duyurusu düzenlendi.`, req));
  res.json(list[idx]);
});

app.delete("/api/announcements/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const list = loadAnnouncements();
  const idx = list.findIndex((a) => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Duyuru bulunamadı." });

  const deleted = list[idx];
  list.splice(idx, 1);
  saveAnnouncements(list);
  appendLog(makeLog("announcement_delete", decoded.email, `"${deleted.title}" duyurusu silindi.`, req));
  res.json({ message: "Duyuru silindi." });
});

app.post("/api/announcements/:id/read", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const list = loadAnnouncements();
  const ann = list.find((a) => a.id === req.params.id);
  if (!ann) return res.status(404).json({ error: "Duyuru bulunamadı." });

  if (!Array.isArray(ann.readBy)) ann.readBy = [];
  if (!ann.readBy.includes(decoded.email)) {
    ann.readBy.push(decoded.email);
    saveAnnouncements(list);
    appendLog(makeLog("announcement_read", decoded.email, `"${ann.title}" duyurusu okundu.`, req));
  }
  res.json({ message: "Okundu." });
});

// ---- Logs ----

const actionLabels = {
  login: "Giriş",
  otp_request: "OTP İsteği",
  user_create: "Kullanıcı Ekleme",
  user_delete: "Kullanıcı Silme",
  user_role_change: "Rol Değiştirme",
  user_import: "Toplu Kullanıcı Yükleme",
  announcement_create: "Duyuru Oluşturma",
  announcement_edit: "Duyuru Düzenleme",
  announcement_delete: "Duyuru Silme",
  announcement_read: "Duyuru Okuma",
  survey_create: "Anket Oluşturma",
  survey_edit: "Anket Düzenleme",
  survey_delete: "Anket Silme",
  survey_respond: "Anket Yanıtlama",
  survey_respond_edit: "Anket Yanıtı Düzenleme",
  file_upload: "Dosya Yükleme",
  file_delete: "Dosya Silme",
  file_download: "Dosya İndirme",
  request_create: "Talep Oluşturma",
  request_edit: "Talep Düzenleme",
  request_delete: "Talep Silme",
  request_respond: "Talep Cevaplama",
  profile_update: "Profil Güncelleme",
  file_request_create: "Belge İstek Oluşturma",
  file_request_submit: "Belge İstek Yükleme",
  file_request_delete: "Belge İstek Silme",
};

app.get("/api/logs", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const allLogs = loadLogs();
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(10, parseInt(req.query.limit) || 50));
  const start = (page - 1) * limit;
  const total = allLogs.length;

  const list = allLogs.slice().reverse().slice(start, start + limit).map((l) => ({
    ...l,
    actionLabel: actionLabels[l.action] || l.action,
    date: new Date(l.timestamp).toLocaleDateString("tr-TR"),
    time: new Date(l.timestamp).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  }));

  res.json({ list, total, page, limit, totalPages: Math.ceil(total / limit) });
});

app.get("/api/logs/export", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const allLogs = loadLogs();
  const lines = [
    "=== SISTEM LOG KAYITLARI ===",
    `Oluşturulma: ${new Date().toLocaleDateString("tr-TR")} ${new Date().toLocaleTimeString("tr-TR")}`,
    `Toplam Kayıt: ${allLogs.length}`,
    "",
    "Tarih         | Saat     | İşlem              | Kullanıcı                         | Detay",
    "".padEnd(120, "-"),
  ];

  allLogs.forEach((l) => {
    const d = new Date(l.timestamp);
    const date = d.toLocaleDateString("tr-TR");
    const time = d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    const action = (actionLabels[l.action] || l.action).padEnd(18);
    const user = l.user.padEnd(34);
    lines.push(`${date} | ${time} | ${action} | ${user} | ${l.detail}`);
  });

  lines.push("", "=== DOSYA SONU ===");

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="sistem-log-${Date.now()}.txt"`);
  res.send(lines.join("\r\n"));
});

// ---- Surveys ----

const SURVEYS_FILE = path.join(DATA_DIR, "surveys.json");
const RESPONSES_FILE = path.join(DATA_DIR, "responses.json");

function loadSurveys() {
  try {
    if (fs.existsSync(SURVEYS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(SURVEYS_FILE, "utf-8"));
      return Array.isArray(raw.surveys) ? raw.surveys : [];
    }
  } catch (_) {}
  return [];
}

function saveSurveys(list) {
  atomicSaveJson(SURVEYS_FILE, JSON.stringify({ surveys: list }, null, 2));
}

function loadResponses() {
  try {
    if (fs.existsSync(RESPONSES_FILE)) {
      const raw = JSON.parse(fs.readFileSync(RESPONSES_FILE, "utf-8"));
      return Array.isArray(raw.responses) ? raw.responses : [];
    }
  } catch (_) {}
  return [];
}

function saveResponses(list) {
  atomicSaveJson(RESPONSES_FILE, JSON.stringify({ responses: list }, null, 2));
}

function isSurveyTargeted(survey, userEmail, userRole, userOwnership) {
  if (survey.targetType === "all") return true;
  if (survey.targetType === "group") return isGroupTargeted(survey, userRole, userOwnership);
  if (survey.targetType === "users") return (survey.targetUsers || []).includes(userEmail);
  return false;
}

app.get("/api/surveys", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const activeRole = resolveRole(user, req);

  const all = loadSurveys();
  const now = Date.now();

  let list;
  if (user.role === "admin") {
    list = all.map((s) => ({
      ...s,
      responseCount: loadResponses().filter((r) => r.surveyId === s.id).length,
    }));
  } else {
    list = all
      .filter((s) => s.expiresAt > now && isSurveyTargeted(s, decoded.email, activeRole, getUserOwnership(users, decoded.email)))
      .map((s) => {
        const myResp = loadResponses().find((r) => r.surveyId === s.id && r.userId === decoded.email);
        return {
          id: s.id,
          title: s.title,
          description: s.description,
          expiresAt: s.expiresAt,
          allowEdit: s.allowEdit,
          submitted: !!myResp,
          submittedAt: myResp ? myResp.submittedAt : null,
          canEdit: s.allowEdit && !!myResp,
        };
      });
  }

  res.json(list);
});

app.post("/api/surveys", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const { title, description, targetType, targetGroup, targetGroups, targetOwnership, targetRoles, targetUsers, expiresInDays, allowEdit, questions } = req.body;
  if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: "Baslik ve en az bir soru gerekli." });
  }
  const validTargets = ["all", "group", "users"];
  if (!validTargets.includes(targetType)) {
    return res.status(400).json({ error: "Geçersiz hedef kitle." });
  }
  const tg = resolveTargetSelection(targetType, req.body);
  if (targetType === "group" && tg.groups.length === 0 && tg.ownership === null) {
    return res.status(400).json({ error: "En az bir grup seçin." });
  }

  const list = loadSurveys();
  const surveyDays = Number(expiresInDays);
  const survey = {
    id: crypto.randomUUID(),
    title,
    description: description || "",
    createdBy: decoded.email,
    createdAt: Date.now(),
    expiresAt: Date.now() + (Number.isFinite(surveyDays) && surveyDays > 0 ? surveyDays : 7) * 24 * 60 * 60 * 1000,
    allowEdit: allowEdit !== false,
    targetType,
    targetGroup: tg.group,
    targetGroups: tg.groups,
    targetOwnership: tg.ownership,
    targetRoles: tg.roles,
    targetUsers: targetType === "users" ? (targetUsers || []) : null,
    questions: questions.map((q, i) => ({
      id: crypto.randomUUID(),
      type: q.type || "open_ended",
      title: q.title,
      required: q.required !== false,
      order: i,
      options: q.options || [],
      validation: q.validation || "none",
    })),
  };
  list.push(survey);
  saveSurveys(list);
  appendLog(makeLog("survey_create", decoded.email, `"${title}" anket oluşturuldu.`, req));
  res.status(201).json(survey);
});

app.get("/api/surveys/:id", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const all = loadSurveys();
  const survey = all.find((s) => s.id === req.params.id);
  if (!survey) return res.status(404).json({ error: "Anket bulunamadı." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });
  const activeRole = resolveRole(user, req);
  if (user.role !== "admin" && !isSurveyTargeted(survey, decoded.email, activeRole, getUserOwnership(users, decoded.email))) {
    return res.status(403).json({ error: "Bu ankete erişim yetkiniz yok." });
  }

  res.json(survey);
});

app.put("/api/surveys/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const list = loadSurveys();
  const idx = list.findIndex((s) => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Anket bulunamadı." });

  const { title, description, targetType, targetGroups, targetUsers, expiresInDays, allowEdit, questions } = req.body;
  if (title) list[idx].title = title;
  if (description !== undefined) list[idx].description = description;
  if (targetType) {
    const validTargets = ["all", "group", "users"];
    if (validTargets.includes(targetType)) {
      list[idx].targetType = targetType;
      if (targetType === "group") {
        const tg = resolveTargetSelection(targetType, req.body);
        const hasNewSel = req.body.targetOwnership !== undefined || req.body.targetRoles !== undefined || (tg.groups || []).length > 0;
        if (hasNewSel) {
          list[idx].targetGroup = tg.group;
          list[idx].targetGroups = tg.groups;
          list[idx].targetOwnership = tg.ownership;
          list[idx].targetRoles = tg.roles;
        }
        const effNew = list[idx].targetOwnership !== undefined && list[idx].targetOwnership !== null;
        const effLegacy = matchedGroups(list[idx]);
        if (!effNew && effLegacy.length === 0) return res.status(400).json({ error: "En az bir grup seçin." });
      } else {
        list[idx].targetGroup = null;
        list[idx].targetGroups = [];
        list[idx].targetOwnership = null;
        list[idx].targetRoles = null;
      }
      list[idx].targetUsers = targetType === "users" ? (targetUsers || []) : null;
    }
  }
  if (expiresInDays !== undefined && expiresInDays !== null && expiresInDays !== "") {
    const days = Number(expiresInDays);
    if (!Number.isFinite(days) || days <= 0) {
      return res.status(400).json({ error: "Gecersiz son tarih." });
    }
    list[idx].expiresAt = Date.now() + days * 24 * 60 * 60 * 1000;
  }
  if (allowEdit !== undefined) list[idx].allowEdit = allowEdit;
  if (questions && Array.isArray(questions) && questions.length > 0) {
    const prev = list[idx].questions || [];
    list[idx].questions = questions.map((q, i) => {
      // id korunur: once client gonderdiyse onu kullan, yoksa ayni siradaki
      // baslik+tip eslesen eski sorunun id'sini devral (eski cevaplari koparma)
      let qid = q.id;
      if (!qid && prev[i] && prev[i].title === q.title && (prev[i].type || "open_ended") === (q.type || "open_ended")) {
        qid = prev[i].id;
      }
      return {
        id: qid || crypto.randomUUID(),
        type: q.type || "open_ended",
        title: q.title,
        required: q.required !== false,
        order: i,
        options: q.options || [],
        validation: q.validation || "none",
      };
    });
  }
  saveSurveys(list);
  appendLog(makeLog("survey_edit", decoded.email, `"${list[idx].title}" ankete duzenlendi.`, req));
  res.json(list[idx]);
});

app.delete("/api/surveys/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const list = loadSurveys();
  const idx = list.findIndex((s) => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Anket bulunamadı." });

  const deleted = list[idx];
  list.splice(idx, 1);
  saveSurveys(list);
  const respList = loadResponses();
  const filtered = respList.filter((r) => r.surveyId !== req.params.id);
  if (filtered.length !== respList.length) saveResponses(filtered);
  appendLog(makeLog("survey_delete", decoded.email, `"${deleted.title}" anket silindi.`, req));
  res.json({ message: "Anket silindi." });
});

app.post("/api/surveys/:id/respond", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const all = loadSurveys();
  const survey = all.find((s) => s.id === req.params.id);
  if (!survey) return res.status(404).json({ error: "Anket bulunamadı." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  if (!isSurveyTargeted(survey, decoded.email, resolveRole(user, req), getUserOwnership(users, decoded.email))) {
    return res.status(403).json({ error: "Bu anket size ait değil." });
  }
  if (survey.expiresAt <= Date.now()) {
    return res.status(400).json({ error: "Anketin süresi dolmuş." });
  }

  const respList = loadResponses();
  const existingIdx = respList.findIndex((r) => r.surveyId === req.params.id && r.userId === decoded.email);
  if (existingIdx !== -1 && !survey.allowEdit) {
    return res.status(400).json({ error: "Bu anketi tekrar gönderemezsiniz." });
  }

  const { answers } = req.body;
  if (!answers || !Array.isArray(answers)) {
    return res.status(400).json({ error: "Cevaplar gerekli." });
  }

  for (const ans of answers) {
    const q = survey.questions.find((x) => x.id === ans.questionId);
    if (!q) continue;
    // Checkbox (çoklu seçim): değer dizi olarak gelir, seçeneklere uygunluğu denetle
    if (q.type === "checkbox") {
      const arr = Array.isArray(ans.value) ? ans.value : ans.value ? [ans.value] : [];
      ans.value = arr.map((v) => (v ?? "").toString());
      if (q.required && arr.length === 0) {
        return res.status(400).json({ error: `"${q.title}" sorusu için en az bir seçenek işaretleyin.` });
      }
      if ((q.options || []).length > 0) {
        const invalid = arr.find((v) => !(q.options || []).includes(v));
        if (invalid !== undefined && arr.length > 0 && invalid) {
          return res.status(400).json({ error: `"${q.title}" sorusu için geçersiz seçenek.` });
        }
      }
      continue;
    }
    const val = (ans.value || "").toString();
    if (q.validation === "number" && val && !/^\d+$/.test(val)) {
      return res.status(400).json({ error: `"${q.title}" sorusu için sadece sayı girin.` });
    }
    if (q.validation === "only_text" && val && /\d/.test(val)) {
      return res.status(400).json({ error: `"${q.title}" sorusu için sadece metin girin.` });
    }
    if (q.validation === "uppercase" && val && val !== val.toUpperCase()) {
      return res.status(400).json({ error: `"${q.title}" sorusunu büyük harfle yazin.` });
    }
    if (q.validation === "email" && val && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
      return res.status(400).json({ error: `"${q.title}" geçerli bir e-posta adresi girin.` });
    }
    if (q.validation === "phone" && val && !/^[\d\s\-()+]{7,15}$/.test(val)) {
      return res.status(400).json({ error: `"${q.title}" geçerli bir telefon numarası girin.` });
    }
  }

  // Zorunlu soru denetimi (tum tipler): eksik ya da bos cevap kabul edilmez
  for (const q of survey.questions) {
    if (!q.required) continue;
    const ans = answers.find((a) => a.questionId === q.id);
    const empty = !ans || (Array.isArray(ans.value) ? ans.value.length === 0 : !(ans.value || "").toString().trim());
    if (empty) {
      return res.status(400).json({ error: `"${q.title}" sorusu zorunlu.` });
    }
  }

  const entry = {
    id: crypto.randomUUID(),
    surveyId: req.params.id,
    userId: decoded.email,
    submittedAt: Date.now(),
    updatedAt: Date.now(),
    answers,
  };

  if (existingIdx !== -1) {
    entry.id = respList[existingIdx].id;
    respList[existingIdx] = entry;
  } else {
    respList.push(entry);
  }
  saveResponses(respList);
  const isEdit = existingIdx !== -1;
  appendLog(makeLog(isEdit ? "survey_respond_edit" : "survey_respond", decoded.email, `"${survey.title}" anketine ${isEdit ? "yanıtı düzenlendi" : "yanıtı eklendi"}.`, req));
  res.json(entry);
});

app.get("/api/surveys/:id/response", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const respList = loadResponses();
  const entry = respList.find((r) => r.surveyId === req.params.id && r.userId === decoded.email);
  if (!entry) return res.status(404).json({ error: "Henüz yanıt vermediniz." });

  res.json(entry);
});

app.get("/api/surveys/:id/responses", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadSurveys();
  const survey = all.find((s) => s.id === req.params.id);
  if (!survey) return res.status(404).json({ error: "Anket bulunamadı." });

  const respList = loadResponses().filter((r) => r.surveyId === req.params.id);
  const users = loadUsers();
  const enriched = respList.map((r) => ({
    ...r,
    userEmail: r.userId,
    schoolName: (users[r.userId]?.profile?.schoolName) || "",
    district: (users[r.userId]?.profile?.district) || "",
    city: (users[r.userId]?.profile?.city) || "",
  }));

  res.json({ survey, responses: enriched });
});

app.get("/api/surveys/:id/responses/export", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadSurveys();
  const survey = all.find((s) => s.id === req.params.id);
  if (!survey) return res.status(404).json({ error: "Anket bulunamadı." });

  const respList = loadResponses().filter((r) => r.surveyId === req.params.id);
  const users = loadUsers();

  const headers = ["Tarih", "Saat", "Kullanıcı", "Okul", "İlçe"];
  survey.questions.forEach((q) => headers.push(q.title));

  const rows = respList.map((r) => {
    const d = new Date(r.submittedAt);
    const date = d.toLocaleDateString("tr-TR");
    const time = d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
    const schoolName = (users[r.userId]?.profile?.schoolName) || "";
    const district = (users[r.userId]?.profile?.district) || "";
    const row = [date, time, r.userId, schoolName, district];
    survey.questions.forEach((q, qi) => {
      let ans = r.answers.find((a) => a.questionId === q.id);
      // Geriye uyumluluk: anket duzenlenmeden once verilen cevaplarda soru
      // id'si tutmayabilir; cevap sayisi soru sayisina esitse sira ile eslestir
      if (!ans && Array.isArray(r.answers) && r.answers.length === survey.questions.length && r.answers[qi]) {
        ans = r.answers[qi];
      }
      const rawVal = ans ? (Array.isArray(ans.value) ? ans.value.join(", ") : (ans.value || "")) : "";
      row.push(ans ? String(rawVal) : "");
    });
    return row.map(csvCell).join(";");
  });

  const csv = "\uFEFF" + headers.map(csvCell).join(";") + "\r\n" + rows.join("\r\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="anket-${survey.id}-${Date.now()}.csv"`);
  res.send(csv);
});

app.get("/api/surveys/:id/status", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadSurveys();
  const survey = all.find((s) => s.id === req.params.id);
  if (!survey) return res.status(404).json({ error: "Anket bulunamadı." });

  const targetUsers = getSurveyStatusUsers(survey);
  const submitted = targetUsers.filter((u) => u.submitted).length;

  res.json({ total: targetUsers.length, submitted, users: targetUsers });
});

function getSurveyStatusUsers(survey) {
  const users = loadUsers();
  const respList = loadResponses().filter((r) => r.surveyId === survey.id);
  return Object.entries(users)
    .filter(([, u]) => {
      if (survey.targetType === "all") return u.role !== "admin";
      if (survey.targetType === "group") return u.role !== "admin" && isGroupTargeted(survey, u.role, (u.profile || {}).ownership || "");
      if (survey.targetType === "users") return (survey.targetUsers || []).includes(u.email);
      return false;
    })
    .map(([email, u]) => ({
      email,
      role: u.role,
      schoolName: (u.profile?.schoolName) || "",
      district: (u.profile?.district) || "",
      city: (u.profile?.city) || "",
      submitted: respList.some((r) => r.userId === email),
      submittedAt: respList.find((r) => r.userId === email)?.submittedAt || null,
    }));
}

// İlçe bazında yanıt durumu: her ilçe için hedef/giren/girmeyen + yüzde
app.get("/api/surveys/:id/district-stats", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadSurveys();
  const survey = all.find((s) => s.id === req.params.id);
  if (!survey) return res.status(404).json({ error: "Anket bulunamadı." });

  const targetUsers = getSurveyStatusUsers(survey);
  const byDistrict = {};
  for (const u of targetUsers) {
    const d = (u.district || "").trim() || "Belirsiz";
    if (!byDistrict[d]) byDistrict[d] = { district: d, total: 0, submitted: 0 };
    byDistrict[d].total++;
    if (u.submitted) byDistrict[d].submitted++;
  }
  const districts = Object.values(byDistrict).map((x) => ({
    ...x,
    pending: x.total - x.submitted,
    rate: x.total > 0 ? Math.round((x.submitted / x.total) * 100) : 0,
  })).sort((a, b) => a.district.localeCompare(b.district, "tr"));
  const submitted = districts.reduce((s, x) => s + x.submitted, 0);

  res.json({
    survey: { id: survey.id, title: survey.title },
    total: targetUsers.length,
    submitted,
    rate: targetUsers.length > 0 ? Math.round((submitted / targetUsers.length) * 100) : 0,
    districts,
  });
});

// Kullanıcı durumu tablosu Excel indir
app.get("/api/surveys/:id/status/export-xlsx", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadSurveys();
  const survey = all.find((s) => s.id === req.params.id);
  if (!survey) return res.status(404).json({ error: "Anket bulunamadı." });

  const XLSX = require("xlsx");
  const roleLabels = { admin: "Yönetici", lise: "Lise", ortaokul: "Ortaokul", diger: "Diğer" };
  const rows = getSurveyStatusUsers(survey).map((u) => ({
    Okul: u.schoolName || "-",
    "İlçe": u.district || "-",
    "E-posta": u.email,
    Grup: roleLabels[u.role] || u.role,
    Durum: u.submitted ? "Yanıtladı" : "Yanıtlamadı",
    Tarih: u.submittedAt ? new Date(u.submittedAt).toLocaleDateString("tr-TR") : "-",
  }));
  const ws = XLSX.utils.json_to_sheet(rows);
  ws["!cols"] = [{ wch: 45 }, { wch: 16 }, { wch: 28 }, { wch: 10 }, { wch: 12 }, { wch: 12 }];
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, "Kullanici Durumu");
  const buf = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", contentDisposition(`anket-${survey.id}-kullanici-durumu.xlsx`));
  res.send(buf);
});

// ---- Files ----

if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + ".zip"),
});
const fileUpload = multer({
  storage: fileStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === ".zip") return cb(null, true);
    cb(new Error("Yalnızca ZIP dosyası kabul edilir."));
  },
});

function loadFiles() {
  try {
    if (fs.existsSync(FILES_FILE)) {
      const raw = JSON.parse(fs.readFileSync(FILES_FILE, "utf-8"));
      return Array.isArray(raw.files) ? raw.files : [];
    }
  } catch (_) {}
  return [];
}

function saveFiles(list) {
  atomicSaveJson(FILES_FILE, JSON.stringify({ files: list }, null, 2));
}

function isFileTargeted(file, userEmail, userRole, userOwnership) {
  if (file.targetType === "all") return true;
  if (file.targetType === "group") return isGroupTargeted(file, userRole, userOwnership);
  if (file.targetType === "users") return (file.targetUsers || []).includes(userEmail);
  return false;
}

app.get("/api/files", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const activeRole = resolveRole(user, req);

  const all = loadFiles();
  const now = Date.now();

  const list = all.filter((f) => {
    if (user.role === "admin") return true;
    return isFileTargeted(f, decoded.email, activeRole, getUserOwnership(users, decoded.email)) && (f.startsAt || 0) <= now && f.expiresAt > now;
  }).map((f) => {
    const dl = f.downloads || [];
    const myDl = dl.find((d) => d.userId === decoded.email);
    return {
      id: f.id,
      originalName: f.originalName,
      size: f.size,
      description: f.description,
      uploadedBy: f.uploadedBy,
      uploadedAt: f.uploadedAt,
      startsAt: f.startsAt || f.uploadedAt,
      expiresAt: f.expiresAt,
      downloaded: !!myDl,
      downloadedAt: myDl ? myDl.downloadedAt : null,
      downloadCount: dl.length,
      ...(user.role === "admin" ? {
        targetType: f.targetType,
        targetGroup: f.targetGroup,
        targetUsers: f.targetUsers,
      } : {}),
    };
  }).reverse();

  res.json(list);
});

app.post("/api/files", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  fileUpload.single("file")(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ error: "Dosya boyutu 10 MB'i gecmemeli." });
        return res.status(400).json({ error: "Dosya yuklenirken hata: " + err.message });
      }
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) return res.status(400).json({ error: "Dosya secilmedi." });
    if (!req.body.description || !req.body.description.trim()) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Aciklama zorunlu." });
    }
    if (!req.body.startsAt) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Indirme baslangic tarihi zorunlu." });
    }
    if (!req.body.expiresAt) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Indirme bitis tarihi zorunlu." });
    }
    if (!Number.isFinite(Number(req.body.startsAt)) || !Number.isFinite(Number(req.body.expiresAt))) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Gecersiz tarih degeri." });
    }
    if (Number(req.body.startsAt) >= Number(req.body.expiresAt)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Baslangic tarihi bitis tarihinden once olmalidir." });
    }
    if (!["all", "group", "users"].includes(req.body.targetType)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Gecersiz hedef kitle." });
    }
    const fileTg = resolveTargetSelection(req.body.targetType, req.body);
    if (req.body.targetType === "group" && fileTg.groups.length === 0 && fileTg.ownership === null) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "En az bir grup seçin." });
    }

    const entry = {
      id: crypto.randomUUID(),
      storedName: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      description: req.body.description.trim(),
      uploadedBy: decoded.email,
      uploadedAt: Date.now(),
      startsAt: Number(req.body.startsAt),
      expiresAt: Number(req.body.expiresAt),
      targetType: req.body.targetType,
      targetGroup: fileTg.group,
      targetGroups: fileTg.groups,
      targetOwnership: fileTg.ownership,
      targetRoles: fileTg.roles,
      targetUsers: req.body.targetType === "users"
        ? (req.body.targetUsers || "").split(",").map((s) => s.trim()).filter(Boolean)
        : null,
      downloads: [],
    };

    const list = loadFiles();
    list.push(entry);
    saveFiles(list);
    appendLog(makeLog("file_upload", decoded.email, `"${entry.originalName}" dosyasi yuklendi (${entry.size} bayt).`, req));
    res.json(entry);
  });
});

app.get("/api/files/:id/download", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const all = loadFiles();
  const file = all.find((f) => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: "Dosya bulunamadı." });

  if (user.role !== "admin") {
    if (!isFileTargeted(file, decoded.email, resolveRole(user, req), getUserOwnership(users, decoded.email))) {
      return res.status(403).json({ error: "Bu dosya size ait değil." });
    }
    const now = Date.now();
    if (file.startsAt && file.startsAt > now) {
      return res.status(400).json({ error: "Bu dosyanın indirme süresi henüz başlamadı." });
    }
    if (file.expiresAt <= now) {
      return res.status(400).json({ error: "Dosyanın indirme süresi dolmuş." });
    }
  }

  const filePath = path.join(UPLOADS_DIR, file.storedName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Dosya diskte bulunamadı." });
  }

  if (!file.downloads) file.downloads = [];
  if (!file.downloads.some((d) => d.userId === decoded.email)) {
    file.downloads.push({ userId: decoded.email, downloadedAt: Date.now() });
    saveFiles(all);
    appendLog(makeLog("file_download", decoded.email, `"${file.originalName}" dosyasi indirildi.`, req));
  }

  res.setHeader("Content-Disposition", contentDisposition(file.originalName));
  res.setHeader("Content-Type", "application/zip");
  res.sendFile(filePath);
});

app.delete("/api/files/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadFiles();
  const idx = all.findIndex((f) => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Dosya bulunamadı." });

  const file = all[idx];
  const filePath = path.join(UPLOADS_DIR, file.storedName);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  all.splice(idx, 1);
  saveFiles(all);
  appendLog(makeLog("file_delete", decoded.email, `"${file.originalName}" dosyasi silindi.`, req));
  res.json({ success: true });
});

app.get("/api/files/:id/status", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadFiles();
  const file = all.find((f) => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: "Dosya bulunamadı." });

  const users = loadUsers();
  const downloads = file.downloads || [];

  const targetUsers = Object.entries(users)
    .filter(([email, u]) => {
      if (file.targetType === "all") return u.role !== "admin";
      if (file.targetType === "group") return u.role !== "admin" && isGroupTargeted(file, u.role, (u.profile || {}).ownership || "");
      if (file.targetType === "users") return (file.targetUsers || []).includes(email);
      return false;
    })
    .map(([email, u]) => {
      const dl = downloads.find((d) => d.userId === email);
      return {
        email,
        role: u.role,
        schoolName: (u.profile?.schoolName) || "",
        district: (u.profile?.district) || "",
        city: (u.profile?.city) || "",
        downloaded: !!dl,
        downloadedAt: dl ? dl.downloadedAt : null,
      };
    });

  res.json({ total: targetUsers.length, downloaded: downloads.length, users: targetUsers });
});

app.get("/api/files/:id/export", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadFiles();
  const file = all.find((f) => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: "Dosya bulunamadı." });

  const users = loadUsers();
  const downloads = file.downloads || [];

  const targetUsers = Object.entries(users)
    .filter(([email, u]) => {
      if (file.targetType === "all") return u.role !== "admin";
      if (file.targetType === "group") return u.role !== "admin" && isGroupTargeted(file, u.role, (u.profile || {}).ownership || "");
      if (file.targetType === "users") return (file.targetUsers || []).includes(email);
      return false;
    })
    .map(([email, u]) => {
      const dl = downloads.find((d) => d.userId === email);
      return {
        email,
        role: u.role,
        schoolName: (u.profile?.schoolName) || "",
        district: (u.profile?.district) || "",
        city: (u.profile?.city) || "",
        downloaded: !!dl,
        downloadedAt: dl ? dl.downloadedAt : null,
      };
    });

  const csv = "\uFEFF" + ["Kullanici", "Rol", "Okul", "İlçe", "Indirme Durumu", "Indirme Tarihi"].join(";") + "\r\n"
    + targetUsers.map((u) => {
      const status = u.downloaded ? "Indirdi" : "Indirmedi";
      const date = u.downloadedAt ? new Date(u.downloadedAt).toLocaleDateString("tr-TR") + " " + new Date(u.downloadedAt).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" }) : "";
      return [u.email, u.role, u.schoolName || "", u.district || "", status, date].map(csvCell).join(";");
    }).join("\r\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="dosya-${file.id}-indirme-durumu-${Date.now()}.csv"`);
  res.send(csv);
});

app.get("/api/reports", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const users = loadUsers();
  const userList = Object.values(users);
  const roleCounts = { admin: 0, lise: 0, ortaokul: 0, diger: 0 };
  userList.forEach((u) => { if (roleCounts[u.role] !== undefined) roleCounts[u.role]++; });
  const totalUsers = userList.length;

  const allLogs = loadLogs();
  const now = Date.now();

  // Monthly activity (last 12 months)
  const monthMap = {};
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now - i * 30 * 24 * 60 * 60 * 1000);
    const key = d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0");
    monthMap[key] = 0;
  }
  allLogs.forEach((l) => {
    const d = new Date(l.timestamp);
    const key = d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0");
    if (monthMap[key] !== undefined) monthMap[key]++;
  });
  const monthlyActivity = Object.entries(monthMap).map(([month, count]) => ({ month, count }));

  // Activity by action
  const actionCounts = {};
  allLogs.forEach((l) => {
    const label = actionLabels[l.action] || l.action;
    actionCounts[label] = (actionCounts[label] || 0) + 1;
  });
  const activityByAction = Object.entries(actionCounts)
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  // Survey stats
  const allSurveys = loadSurveys();
  const allResponses = loadResponses();
  const surveyStats = allSurveys.map((s) => {
    const respCount = allResponses.filter((r) => r.surveyId === s.id).length;
    let targetCount = 0;
    if (s.targetType === "all") targetCount = userList.filter((u) => u.role !== "admin").length;
    else if (s.targetType === "group") targetCount = countItemTargets(userList, s);
    else if (s.targetType === "users") targetCount = (s.targetUsers || []).length;
    return {
      id: s.id,
      title: s.title,
      targetCount,
      respCount,
      rate: targetCount > 0 ? Math.round((respCount / targetCount) * 100) : 0,
    };
  }).sort((a, b) => b.respCount - a.respCount);

  // File download stats
  const allFiles = loadFiles();
  const topFiles = allFiles.map((f) => ({
    name: f.originalName,
    downloads: (f.downloads || []).length,
  })).sort((a, b) => b.downloads - a.downloads).slice(0, 10);

  // Announcement read stats
  const allAnn = loadAnnouncements();
  const annReadStats = allAnn.map((a) => {
    const readCount = (a.readBy || []).length;
    const targetUserCount = (() => {
      if (a.target === "all") return userList.filter((u) => u.role !== "admin").length;
      return countItemTargets(userList, a);
    })();
    return {
      title: a.title,
      readCount,
      targetCount: targetUserCount,
      rate: targetUserCount > 0 ? Math.round((readCount / targetUserCount) * 100) : 0,
    };
  });

  // Last 7 days activity
  const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;
  const recentLogs = allLogs.filter((l) => l.timestamp > sevenDaysAgo);
  const dailyMap = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now - i * 24 * 60 * 60 * 1000);
    const key = d.toLocaleDateString("tr-TR");
    dailyMap[key] = 0;
  }
  recentLogs.forEach((l) => {
    const key = new Date(l.timestamp).toLocaleDateString("tr-TR");
    if (dailyMap[key] !== undefined) dailyMap[key]++;
  });
  const dailyActivity = Object.entries(dailyMap).map(([day, count]) => ({ day, count }));

  // File totals
  const totalFileUploads = allFiles.length;
  const totalFileDownloads = allFiles.reduce((sum, f) => sum + (f.downloads || []).length, 0);

  // Overall avg read rate
  const totalAnnReads = allAnn.reduce((s, a) => s + (a.readBy || []).length, 0);
  const totalAnnTargets = allAnn.reduce((s, a) => {
    if (a.target === "all") return s + userList.filter((u) => u.role !== "admin").length;
    return s + countItemTargets(userList, a);
  }, 0);

  res.json({
    users: {
      total: totalUsers,
      admin: roleCounts.admin,
      lise: roleCounts.lise,
      ortaokul: roleCounts.ortaokul,
      diger: roleCounts.diger,
    },
    monthlyActivity,
    dailyActivity,
    activityByAction,
    surveyStats: surveyStats.slice(0, 10),
    topFiles,
    annReadStats,
    totals: {
      surveys: allSurveys.length,
      responses: allResponses.length,
      files: totalFileUploads,
      fileDownloads: totalFileDownloads,
      announcements: allAnn.length,
      avgReadRate: totalAnnTargets > 0 ? Math.round((totalAnnReads / totalAnnTargets) * 100) : 0,
    },
  });
});

// ---- Requests (Talep/İtiraz) ----

const REQUESTS_FILE = path.join(DATA_DIR, "requests.json");
const REQUESTS_UPLOADS_DIR = path.join(UPLOADS_DIR, "requests");

if (!fs.existsSync(REQUESTS_UPLOADS_DIR)) {
  fs.mkdirSync(REQUESTS_UPLOADS_DIR, { recursive: true });
}

const requestStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, REQUESTS_UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname)),
});
const requestUpload = multer({
  storage: requestStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const allowed = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".zip"];
    if (allowed.includes(ext)) return cb(null, true);
    cb(new Error("Desteklenmeyen dosya türü. İzin verilen: PDF, Word, Excel, JPG, PNG, ZIP."));
  },
});

function loadRequests() {
  try {
    if (fs.existsSync(REQUESTS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(REQUESTS_FILE, "utf-8"));
      return Array.isArray(raw.requests) ? raw.requests : [];
    }
  } catch (_) {}
  return [];
}

function saveRequests(list) {
  atomicSaveJson(REQUESTS_FILE, JSON.stringify({ requests: list }, null, 2));
}

const requestTypes = ["talep", "oneri", "sikayet", "itiraz"];
const requestTypeLabels = { talep: "Talep", oneri: "Öneri", sikayet: "Şikayet", itiraz: "İtiraz" };

app.get("/api/requests", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const all = loadRequests();
  const list = all
    .filter((r) => user.role === "admin" || r.submittedBy === decoded.email)
    .map((r) => ({
      id: r.id,
      type: r.type,
      typeLabel: requestTypeLabels[r.type] || r.type,
      title: r.title,
      description: r.description,
      officialDocNo: r.officialDocNo || null,
      hasAttachment: !!r.storedName,
      originalName: r.originalName || null,
      submittedBy: r.submittedBy,
      schoolName: r.schoolName || "",
      district: (users[r.submittedBy]?.profile?.district) || r.district || "",
      city: (users[r.submittedBy]?.profile?.city) || r.city || "",
      submittedAt: r.submittedAt,
      status: r.status,
      responseCount: (r.responses || []).length,
      lastResponseAt: (r.responses && r.responses.length > 0) ? r.responses[r.responses.length - 1].respondedAt : null,
    }))
    .reverse();

  res.json(list);
});

app.get("/api/requests/:id", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const all = loadRequests();
  const reqEntry = all.find((r) => r.id === req.params.id);
  if (!reqEntry) return res.status(404).json({ error: "Talep bulunamadı." });

  if (user.role !== "admin" && reqEntry.submittedBy !== decoded.email) {
    return res.status(403).json({ error: "Bu talebe erişim yetkiniz yok." });
  }

  res.json({
    ...reqEntry,
    district: (users[reqEntry.submittedBy]?.profile?.district) || reqEntry.district || "",
    city: (users[reqEntry.submittedBy]?.profile?.city) || reqEntry.city || "",
    hasAttachment: !!reqEntry.storedName,
    typeLabel: requestTypeLabels[reqEntry.type] || reqEntry.type,
  });
});

app.post("/api/requests", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });
  if (user.role === "admin") return res.status(403).json({ error: "Admin talep gönderemez." });

  requestUpload.single("file")(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") return res.status(400).json({ error: "Dosya boyutu 10 MB'i gecmemeli." });
        return res.status(400).json({ error: "Dosya yuklenirken hata: " + err.message });
      }
      return res.status(400).json({ error: err.message });
    }

    const { type, title, description, officialDocNo } = req.body;
    if (!type || !requestTypes.includes(type)) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Geçerli bir talep türü seçin: talep, öneri, şikayet, itiraz." });
    }
    if (!title || !title.trim()) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Başlık zorunlu." });
    }
    if (!description || !description.trim()) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Açıklama zorunlu." });
    }

    const list = loadRequests();
    const entry = {
      id: crypto.randomUUID(),
      type,
      title: title.trim(),
      description: description.trim(),
      officialDocNo: (officialDocNo || "").trim() || null,
      submittedBy: decoded.email,
      schoolName: (user.profile?.schoolName) || "",
      district: (user.profile?.district) || "",
      city: (user.profile?.city) || "",
      submittedAt: Date.now(),
      status: "open",
      responses: [],
      storedName: req.file ? req.file.filename : null,
      originalName: req.file ? req.file.originalname : null,
    };
    list.push(entry);
    saveRequests(list);
    appendLog(makeLog("request_create", decoded.email, `"${entry.title}" talebi oluşturuldu (${entry.type}).`, req));
    res.status(201).json(entry);
  });
});

app.put("/api/requests/:id", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });
  if (user.role === "admin") return res.status(403).json({ error: "Admin talep duzenleyemez." });

  const all = loadRequests();
  const idx = all.findIndex((r) => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Talep bulunamadı." });
  if (all[idx].submittedBy !== decoded.email) return res.status(403).json({ error: "Bu talebi duzenleyemezsiniz." });
  if (all[idx].status !== "open") return res.status(400).json({ error: "Sadece acik talepler duzenlenebilir." });

  const { title, description, officialDocNo } = req.body;
  if (title) all[idx].title = title.trim();
  if (description) all[idx].description = description.trim();
  if (officialDocNo !== undefined) all[idx].officialDocNo = (officialDocNo || "").trim() || null;

  saveRequests(all);
  appendLog(makeLog("request_edit", decoded.email, `"${all[idx].title}" talebi duzenlendi.`, req));
  res.json(all[idx]);
});

app.delete("/api/requests/:id", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const all = loadRequests();
  const idx = all.findIndex((r) => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Talep bulunamadı." });

  const entry = all[idx];
  if (user.role !== "admin" && entry.submittedBy !== decoded.email) {
    return res.status(403).json({ error: "Bu talebi silemezsiniz." });
  }
  if (user.role !== "admin" && entry.status !== "open") {
    return res.status(400).json({ error: "Sadece açık talepler silinebilir." });
  }

  if (entry.storedName) {
    const filePath = path.join(REQUESTS_UPLOADS_DIR, entry.storedName);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }

  all.splice(idx, 1);
  saveRequests(all);
  appendLog(makeLog("request_delete", decoded.email, `"${entry.title}" talebi silindi.`, req));
  res.json({ success: true });
});

app.post("/api/requests/:id/respond", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadRequests();
  const idx = all.findIndex((r) => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Talep bulunamadı." });

  const { message, close } = req.body;
  if (!message || !message.trim()) {
    return res.status(400).json({ error: "Cevap mesajı zorunlu." });
  }

  const response = {
    id: crypto.randomUUID(),
    adminEmail: decoded.email,
    message: message.trim(),
    respondedAt: Date.now(),
  };

  if (!all[idx].responses) all[idx].responses = [];
  all[idx].responses.push(response);

  if (close === true || close === "true") {
    all[idx].status = "closed";
  }

  saveRequests(all);
  appendLog(makeLog("request_respond", decoded.email, `"${all[idx].title}" talebine cevap verildi${all[idx].status === "closed" ? " ve kapatildi" : ""}.`, req));
  res.json({ response, status: all[idx].status });
});

app.get("/api/requests/:id/attachment", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanıcı bulunamadı." });

  const all = loadRequests();
  const entry = all.find((r) => r.id === req.params.id);
  if (!entry) return res.status(404).json({ error: "Talep bulunamadı." });

  if (user.role !== "admin" && entry.submittedBy !== decoded.email) {
    return res.status(403).json({ error: "Bu talebe erişim yetkiniz yok." });
  }

  if (!entry.storedName) return res.status(404).json({ error: "Bu talebe ek dosya bulunmuyor." });

  const filePath = path.join(REQUESTS_UPLOADS_DIR, entry.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Dosya diskte bulunamadı." });

  const isPreview = req.query.preview === "1";
  if (isPreview) {
    const ext = path.extname(entry.originalName || "").toLowerCase();
    const mimeMap = {
      ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
      ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
      ".pdf": "application/pdf",
    };
    const contentType = mimeMap[ext] || "application/octet-stream";
    res.setHeader("Content-Type", contentType);
    res.setHeader("Content-Disposition", contentDisposition(entry.originalName, "inline"));
  } else {
    res.setHeader("Content-Disposition", contentDisposition(entry.originalName));
  }
  res.sendFile(filePath);
});

// ---- File Requests ----

const FILE_REQUESTS_UPLOADS_DIR = path.join(UPLOADS_DIR, "file-requests");

function loadFileRequests() {
  try {
    if (fs.existsSync(FILE_REQUESTS_FILE)) {
      const data = JSON.parse(fs.readFileSync(FILE_REQUESTS_FILE, "utf-8"));
      return Array.isArray(data) ? data : (data.requests || []);
    }
  } catch (_) {}
  return [];
}

function saveFileRequests(list) {
  atomicSaveJson(FILE_REQUESTS_FILE, JSON.stringify({ requests: list }, null, 2));
}

const frTempDir = path.join(FILE_REQUESTS_UPLOADS_DIR, "temp");
if (!fs.existsSync(frTempDir)) fs.mkdirSync(frTempDir, { recursive: true });
const frUpload = multer({
  dest: frTempDir,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (path.extname(file.originalname).toLowerCase() !== ".zip")
      return cb(new Error("Yalnızca ZIP dosyalarına izin verilir."));
    cb(null, true);
  },
});

function isFrTargeted(fr, userEmail, userRole, userOwnership) {
  if (fr.targetType === "all") return true;
  if (fr.targetType === "group") return isGroupTargeted(fr, userRole, userOwnership);
  if (fr.targetType === "users") return (fr.targetUsers || []).includes(userEmail);
  return false;
}

app.get("/api/file-requests", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanici bulunamadi." });

  const activeRole = resolveRole(user, req);
  const all = loadFileRequests();
  const now = Date.now();

  let list;
  if (user.role === "admin") {
    list = all.map((fr) => ({
      ...fr,
      submissionCount: (fr.submissions || []).length,
    }));
  } else {
    list = all
      .filter((fr) => fr.expiresAt > now && isFrTargeted(fr, decoded.email, activeRole, getUserOwnership(users, decoded.email)))
      .map((fr) => {
        const mySub = (fr.submissions || []).find((s) => s.userEmail === decoded.email);
        return {
          id: fr.id,
          title: fr.title,
          description: fr.description,
          expiresAt: fr.expiresAt,
          submitted: !!mySub,
          submittedAt: mySub ? mySub.submittedAt : null,
        };
      });
  }

  res.json(list);
});

app.post("/api/file-requests", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const { title, description, targetType, targetUsers, expiresInDays } = req.body;
  if (!title || !targetType) {
    return res.status(400).json({ error: "Baslik ve hedef tipi gerekli." });
  }
  if (!["all", "group", "users"].includes(targetType)) {
    return res.status(400).json({ error: "Gecersiz hedef kitle." });
  }
  const frTg = resolveTargetSelection(targetType, req.body);
  if (targetType === "group" && frTg.groups.length === 0 && frTg.ownership === null) {
    return res.status(400).json({ error: "En az bir grup seçin." });
  }
  const frDays = Number(expiresInDays);
  const validFrDays = Number.isFinite(frDays) && frDays > 0 ? frDays : 7;

  const fr = {
    id: crypto.randomUUID(),
    title: title.trim(),
    description: description ? description.trim() : "",
    targetType,
    targetGroup: frTg.group,
    targetGroups: frTg.groups,
    targetOwnership: frTg.ownership,
    targetRoles: frTg.roles,
    targetUsers: targetType === "users" ? (targetUsers || []).map((e) => e.toLowerCase().trim()) : null,
    createdAt: Date.now(),
    expiresAt: Date.now() + validFrDays * 24 * 60 * 60 * 1000,
    submissions: [],
    createdBy: decoded.email,
  };

  const all = loadFileRequests();
  all.push(fr);
  saveFileRequests(all);
  appendLog(makeLog("file_request_create", decoded.email, `Dosya talebi oluşturuldu: ${fr.title}`, req));
  res.json(fr);
});

app.post("/api/file-requests/:id/submit", frUpload.array("files", 10), (req, res) => {
  const decoded = authUser(req);
  if (!decoded) {
    cleanupUploadedFiles(req);
    return res.status(401).json({ error: "Token gerekli." });
  }

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) {
    cleanupUploadedFiles(req);
    return res.status(403).json({ error: "Kullanici bulunamadi." });
  }

  const activeRole = resolveRole(user, req);
  const all = loadFileRequests();
  const idx = all.findIndex((fr) => fr.id === req.params.id);
  if (idx === -1) {
    cleanupUploadedFiles(req);
    return res.status(404).json({ error: "Talep bulunamadi." });
  }

  const fr = all[idx];
  if (fr.expiresAt < Date.now()) {
    cleanupUploadedFiles(req);
    return res.status(400).json({ error: "Bu talebin süresi dolmus." });
  }

  if (!isFrTargeted(fr, decoded.email, activeRole, getUserOwnership(users, decoded.email))) {
    cleanupUploadedFiles(req);
    return res.status(403).json({ error: "Bu talep size ait degil." });
  }

  if ((fr.submissions || []).some((s) => s.userEmail === decoded.email)) {
    cleanupUploadedFiles(req);
    return res.status(400).json({ error: "Bu talebe zaten dosya gönderdiniz." });
  }

  if (!req.files || req.files.length === 0) {
    cleanupUploadedFiles(req);
    return res.status(400).json({ error: "En az bir ZIP dosyasi yükleyin." });
  }

  if (!fs.existsSync(FILE_REQUESTS_UPLOADS_DIR))
    fs.mkdirSync(FILE_REQUESTS_UPLOADS_DIR, { recursive: true });

  const subId = crypto.randomUUID();
  const subDir = path.join(FILE_REQUESTS_UPLOADS_DIR, subId);
  fs.mkdirSync(subDir, { recursive: true });

  const savedFiles = req.files.map((f) => {
    const ext = path.extname(f.originalname);
    const safeName = subId + "-" + Date.now() + "-" + Math.random().toString(36).slice(2, 6) + ext;
    const dest = path.join(subDir, safeName);
    fs.renameSync(f.path, dest);
    return { originalName: f.originalname, storedName: safeName, size: f.size };
  });

  const submission = {
    id: subId,
    userEmail: decoded.email,
    userRole: user.role,
    submittedAt: Date.now(),
    files: savedFiles,
  };

  if (!fr.submissions) fr.submissions = [];
  fr.submissions.push(submission);
  saveFileRequests(all);

  appendLog(makeLog("file_request_submit", decoded.email, `${decoded.email} dosya gönderdi: ${fr.title}`, req));
  res.json(submission);
});

app.get("/api/file-requests/:id", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const all = loadFileRequests();
  const fr = all.find((fr) => fr.id === req.params.id);
  if (!fr) return res.status(404).json({ error: "Talep bulunamadi." });

  const allUsers = loadUsers();
  const liveUser = allUsers[decoded.email];
  if (!liveUser) return res.status(403).json({ error: "Kullanici bulunamadi." });

  if (liveUser.role !== "admin") {
    const activeRole = resolveRole(liveUser, req);
    if (!isFrTargeted(fr, decoded.email, activeRole, getUserOwnership(allUsers, decoded.email)))
      return res.status(403).json({ error: "Bu talep size ait degil." });
    fr.submissions = (fr.submissions || []).filter((s) => s.userEmail === decoded.email);
  }

  if (liveUser.role === "admin" && fr.submissions) {
    fr.submissions = fr.submissions.map((s) => ({
      ...s,
      userSchool: allUsers[s.userEmail]?.profile?.schoolName || "",
      userDistrict: allUsers[s.userEmail]?.profile?.district || "",
      userCity: allUsers[s.userEmail]?.profile?.city || "",
    }));
  }

  res.json(fr);
});

app.delete("/api/file-requests/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadFileRequests();
  const idx = all.findIndex((fr) => fr.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Talep bulunamadi." });

  const removed = all.splice(idx, 1)[0];
  saveFileRequests(all);

  (removed.submissions || []).forEach((s) => {
    const subDir = path.join(FILE_REQUESTS_UPLOADS_DIR, s.id);
    if (fs.existsSync(subDir)) fs.rmSync(subDir, { recursive: true, force: true });
  });

  appendLog(makeLog("file_request_delete", decoded.email, `Dosya talebi silindi: ${removed.title}`, req));
  res.json({ success: true });
});

app.get("/api/file-requests/:id/download-all", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const all = loadFileRequests();
  const fr = all.find((fr) => fr.id === req.params.id);
  if (!fr) return res.status(404).json({ error: "Talep bulunamadi." });

  const submissions = fr.submissions || [];
  if (submissions.length === 0) return res.status(404).json({ error: "Gönderi yok." });

  const archiver = require("archiver");
  const archive = archiver("zip", { zlib: { level: 5 } });
  const sanitized = fr.title.replace(/[^a-zA-Z0-9\- _]/g, "_").substring(0, 50);
  const zipName = `belge_istegi_${sanitized}.zip`;

  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", `attachment; filename="${zipName}"`);

  archive.pipe(res);

  const allUsers = loadUsers();
  for (const sub of submissions) {
    const school = allUsers[sub.userEmail]?.profile?.schoolName || sub.userEmail;
    const folder = school.replace(/[^a-zA-Z0-9\- _]/g, "_").substring(0, 40);
    for (const file of (sub.files || [])) {
      const filePath = path.join(FILE_REQUESTS_UPLOADS_DIR, sub.id, file.storedName);
      if (fs.existsSync(filePath)) {
        const entryName = String(file.originalName || "dosya").replace(/[/\\]/g, "_").replace(/\.\./g, "_");
        archive.file(filePath, { name: `${folder}/${entryName}` });
      }
    }
  }

  archive.on("error", (err) => {
    console.error("ZIP olusturma hatasi:", err.message);
    if (!res.headersSent) res.status(500);
    res.end();
  });
  archive.finalize().catch((err) => {
    console.error("ZIP finalize hatasi:", err.message);
    if (!res.headersSent) res.status(500);
    res.end();
  });
});

app.get("/api/file-requests/:id/download/:submissionId/:fileIndex", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const all = loadFileRequests();
  const fr = all.find((fr) => fr.id === req.params.id);
  if (!fr) return res.status(404).json({ error: "Talep bulunamadi." });

  const sub = (fr.submissions || []).find((s) => s.id === req.params.submissionId);
  if (!sub) return res.status(404).json({ error: "Gönderi bulunamadi." });

  // Admin tümünü, okul yalnızca kendi gönderisini indirebilir
  const users = loadUsers();
  const isAdmin = users[decoded.email] && users[decoded.email].role === "admin";
  if (!isAdmin && sub.userEmail !== decoded.email) {
    return res.status(403).json({ error: "Bu dosyayı indirme yetkiniz yok." });
  }

  const fileIdx = parseInt(req.params.fileIndex, 10);
  const file = sub.files[fileIdx];
  if (!file) return res.status(404).json({ error: "Dosya bulunamadi." });

  const filePath = path.join(FILE_REQUESTS_UPLOADS_DIR, sub.id, file.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Dosya sunucuda bulunamadi." });

  res.download(filePath, file.originalName);
});

// ---- CSP ihlal raporu (rapor modu; log dosyasina yazilmaz, sadece konsola) ----
app.post("/api/csp-report", (req, res) => {
  try {
    const r = (req.body && (req.body["csp-report"] || req.body)) || {};
    console.warn("[CSP]", r["violated-directive"] || r.directive || "?", "->", (r["blocked-uri"] || r.blockedURL || "?").toString().slice(0, 200));
  } catch (_) {}
  res.status(204).end();
});

// ---- Verify Token ----

app.get("/api/verify-token", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ valid: false });
  }
  try {
    jwt.verify(auth.split(" ")[1], JWT_SECRET);
    res.json({ valid: true });
  } catch (_) {
    res.json({ valid: false });
  }
});

seedInitialAdmin();

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server http://localhost:${PORT} adresinde çalışıyor`);
});

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

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const USERS_FILE = path.join(DATA_DIR, "users.json");
const ANNOUNCEMENTS_FILE = path.join(DATA_DIR, "announcements.json");
const LOGS_FILE = path.join(DATA_DIR, "logs.json");
const FILES_FILE = path.join(DATA_DIR, "files.json");
const UPLOADS_DIR = path.join(DATA_DIR, "uploads");

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
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
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
  fs.writeFileSync(ANNOUNCEMENTS_FILE, JSON.stringify({ announcements: list }, null, 2));
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
  fs.writeFileSync(LOGS_FILE, JSON.stringify({ logs: list }, null, 2));
}

function makeLog(action, user, detail, req) {
  return {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    action,
    user,
    detail,
    ip: req ? req.ip || req.connection?.remoteAddress || "?" : "?",
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
  windowMs: OTP_COOLDOWN_MS,
  max: 1,
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
  await transporter.sendMail({
    from: `"OTP Girişi" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "OTP Doğrulama Kodu",
    html: `
      <div style="font-family: Arial; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
        <h2 style="color: #333;">OTP Doğrulama Kodu</h2>
        <p>Aşağıdaki kodu kullanarak sisteme giriş yapabilirsiniz:</p>
        <div style="font-size: 32px; font-weight: bold; color: #2563eb; text-align: center; padding: 20px; letter-spacing: 8px;">
          ${otp}
        </div>
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
    (a) => a.target === "all" || a.target === role || (role === "diger" && a.target === "diger")
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

  const roleData = {
    admin: {
      announcements: filteredAnn,
      links: [
        { title: "Kullanıcı Yönetimi", url: "/navigate/users", icon: "fa-users-gear", desc: "Kullanıcı rollerini yönetin" },
        { title: "Duyuru Panosu", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler" },
        { title: "Dosya Yönetimi", url: "/navigate/files", icon: "fa-folder", desc: "Belge ve dosya paylaşımı" },
        { title: "Anketler", url: "/navigate/surveys", icon: "fa-square-poll-vertical", desc: "Anketleri oluşturun ve sonuçları görüntüleyin" },
        { title: "Log Kayıtları", url: "/navigate/logs", icon: "fa-clipboard-list", desc: "Sistem hareketlerini inceleyin" },
        { title: "Raporlar", url: "/navigate/reports", icon: "fa-chart-bar", desc: "İstatistik ve grafik raporları" },
        { title: "Sistem Ayarları", url: "#", icon: "fa-sliders", desc: "Genel sistem yapılandırması" },
        { title: "Diğerleri", url: "#", icon: "fa-ellipsis-h", desc: "Diğer sistem araçları" },
      ],
      stats: [
        { label: "Toplam Kullanıcı", value: String(totalUsers), icon: "fa-users", color: "#6366f1" },
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
        { title: "Dosyalar", url: "/navigate/files", icon: "fa-folder-open", desc: "Gönderilen dosyaları indirin" },
      ],
    },
    ortaokul: {
      announcements: filteredAnn,
      stats: buildProfileStats(users, email),
      links: [
        { title: "Duyurular", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler" },
        { title: "Anketler", url: "/navigate/surveys", icon: "fa-square-poll-vertical", desc: "Anketleri görüntüleyin ve yanıtlayın" },
        { title: "Dosyalar", url: "/navigate/files", icon: "fa-folder-open", desc: "Gönderilen dosyaları indirin" },
      ],
    },
    diger: {
      announcements: filteredAnn,
      stats: buildProfileStats(users, email),
      links: [
        { title: "Duyurular", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler" },
        { title: "Anketler", url: "/navigate/surveys", icon: "fa-square-poll-vertical", desc: "Anketleri görüntüleyin ve yanıtlayın" },
        { title: "Dosyalar", url: "/navigate/files", icon: "fa-folder-open", desc: "Gönderilen dosyaları indirin" },
      ],
    },
  };

  if (role !== "admin" && roleData[role]) {
    const unreadAnn = filteredAnn.filter((a) => !a.read).length;

    const allSurveyList = loadSurveys();
    const activeSurveys = allSurveyList.filter((s) => s.expiresAt > now);
    const targetedSurveys = activeSurveys.filter((s) => isSurveyTargeted(s, email, role));
    const allResp = loadResponses();
    const userResp = allResp.filter((r) => r.userId === email);
    const unansweredSurveys = targetedSurveys.filter((s) => !userResp.some((r) => r.surveyId === s.id)).length;

    const allFileList = loadFiles();
    const targetedFiles = allFileList.filter((f) => (f.startsAt || 0) <= now && f.expiresAt > now && isFileTargeted(f, email, role));
    const undownloadedFiles = targetedFiles.filter((f) => !(f.downloads || []).some((d) => d.userId === email)).length;

    if (roleData[role] && roleData[role].links) {
      roleData[role].links[0].badge = unreadAnn;
      roleData[role].links[1].badge = unansweredSurveys;
      roleData[role].links[2].badge = undownloadedFiles;
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

app.post("/api/send-otp", async (req, res) => {
  try {
    const { email, captchaId, captcha } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Gecerli bir e-posta adresi girin." });
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
      return res.status(403).json({ error: "Bu e-posta adresi sistemde kayıtlı değil. Yetkili kişilerle iletişime geçin." });
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
    otpStore.set(normEmail, { otp, expires: now + OTP_EXPIRY_MS, sentAt: now });
    lastOtpRequest.set(normEmail, now);

    await sendOtpEmail(normEmail, otp);
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
    if (now - failData.firstAttempt < LOCKOUT_DURATION_MS) {
      const remaining = Math.ceil((LOCKOUT_DURATION_MS - (now - failData.firstAttempt)) / 1000);
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
  if (record.otp !== otp) {
    if (!failData) {
      failedAttempts.set(normEmail, { count: 1, firstAttempt: now });
    } else {
      failData.count += 1;
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
  const user = users[decoded.email] || { email: decoded.email, role: "admin" };
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
  users[decoded.email].profile = {
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
    const user = users[decoded.email] || { email: decoded.email, role: "admin" };
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
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const list = Object.entries(users).map(([email, data]) => ({
    email,
    role: data.role || "admin",
    crossRoles: data.crossRoles || [],
    profile: data.profile || null,
    created: data.created,
    lastLogin: data.lastLogin,
  }));
  res.json(list);
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

  const { email, role } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Geçerli bir e-posta adresi girin." });
  }
  const validRoles = ["admin", "lise", "ortaokul", "diger"];
  const userRole = validRoles.includes(role) ? role : detectRole(email);

  const normEmail = email.toLowerCase().trim();
  const users = loadUsers();
  if (users[normEmail]) {
    return res.status(409).json({ error: "Bu e-posta adresi zaten kayıtlı." });
  }

  const schoolMatch = normEmail.match(/^(\d+)@meb\.(gov\.tr|k12\.tr)$/);
  users[normEmail] = {
    email: normEmail,
    role: userRole,
    created: Date.now(),
    lastLogin: null,
    profile: schoolMatch ? { schoolCode: schoolMatch[1] } : undefined,
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

  const { role, crossRoles } = req.body;
  const validRoles = ["admin", "lise", "ortaokul", "diger"];
  const currentRole = role && validRoles.includes(role) ? role : users[normEmail].role;
  if (role && validRoles.includes(role) && role !== users[normEmail].role) {
    const oldRole = users[normEmail].role;
    users[normEmail].role = role;
    appendLog(makeLog("user_role_change", decoded.email, `${normEmail}: ${oldRole} -> ${role}`, req));
  }
  if (crossRoles !== undefined) {
    const validCross = crossRoles.filter((r) => validRoles.includes(r) && r !== currentRole);
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
      let added = 0, updated = 0, errors = [];
      const colMap = { il: null, ilce: null, genelMudurluk: null, kurumTuru: null, kurumKodu: null, kurum: null };
      function normalizeCol(s) {
        return s.toLowerCase().replace(/[\s\-_]/g, "").replace(/ü/g, "u").replace(/ğ/g, "g").replace(/ı/g, "i").replace(/ş/g, "s").replace(/ö/g, "o").replace(/ç/g, "c");
      }
      const firstRow = rows[0];
      for (const key of Object.keys(firstRow)) {
        const k = normalizeCol(key);
        if (k.includes("ilce")) colMap.ilce = key;
        else if (k === "il") colMap.il = key;
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
      res.json({ added, updated, errors: errors.length > 0 ? errors.slice(0, 10) : [] });
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
      .filter((a) => a.expiresAt > now && (a.target === "all" || a.target === activeRole))
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

  const { title, content, target, expiresInDays } = req.body;
  if (!title || !content || !target) {
    return res.status(400).json({ error: "Başlık, içerik ve hedef kitle gerekli." });
  }
  const validTargets = ["all", "lise", "ortaokul", "diger"];
  if (!validTargets.includes(target)) {
    return res.status(400).json({ error: "Geçersiz hedef kitle." });
  }

  const list = loadAnnouncements();
  const ann = {
    id: crypto.randomUUID(),
    title,
    content,
    target,
    createdBy: decoded.email,
    createdAt: Date.now(),
    expiresAt: Date.now() + (expiresInDays || 7) * 24 * 60 * 60 * 1000,
    readBy: [],
  };
  list.push(ann);
  saveAnnouncements(list);
  appendLog(makeLog("announcement_create", decoded.email, `"${title}" duyurusu oluşturuldu (hedef: ${target}).`, req));
  res.status(201).json(ann);
});

app.put("/api/announcements/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const list = loadAnnouncements();
  const idx = list.findIndex((a) => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Duyuru bulunamadı." });

  const { title, content, target, expiresInDays } = req.body;
  if (title) list[idx].title = title;
  if (content) list[idx].content = content;
  if (target) {
    const validTargets = ["all", "lise", "ortaokul", "diger"];
    if (validTargets.includes(target)) list[idx].target = target;
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
  fs.writeFileSync(SURVEYS_FILE, JSON.stringify({ surveys: list }, null, 2));
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
  fs.writeFileSync(RESPONSES_FILE, JSON.stringify({ responses: list }, null, 2));
}

function isSurveyTargeted(survey, userEmail, userRole) {
  if (survey.targetType === "all") return true;
  if (survey.targetType === "group") return survey.targetGroup === userRole;
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
      .filter((s) => s.expiresAt > now && isSurveyTargeted(s, decoded.email, activeRole))
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

  const { title, description, targetType, targetGroup, targetUsers, expiresInDays, allowEdit, questions } = req.body;
  if (!title || !questions || !Array.isArray(questions) || questions.length === 0) {
    return res.status(400).json({ error: "Baslik ve en az bir soru gerekli." });
  }
  const validTargets = ["all", "group", "users"];
  if (!validTargets.includes(targetType)) {
    return res.status(400).json({ error: "Geçersiz hedef kitle." });
  }

  const list = loadSurveys();
  const survey = {
    id: crypto.randomUUID(),
    title,
    description: description || "",
    createdBy: decoded.email,
    createdAt: Date.now(),
    expiresAt: Date.now() + (expiresInDays || 7) * 24 * 60 * 60 * 1000,
    allowEdit: allowEdit !== false,
    targetType,
    targetGroup: targetType === "group" ? targetGroup : null,
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
  if (user.role !== "admin" && !isSurveyTargeted(survey, decoded.email, user.role)) {
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

  const { title, description, targetType, targetGroup, targetUsers, expiresInDays, allowEdit, questions } = req.body;
  if (title) list[idx].title = title;
  if (description !== undefined) list[idx].description = description;
  if (targetType) {
    const validTargets = ["all", "group", "users"];
    if (validTargets.includes(targetType)) {
      list[idx].targetType = targetType;
      list[idx].targetGroup = targetType === "group" ? targetGroup : null;
      list[idx].targetUsers = targetType === "users" ? (targetUsers || []) : null;
    }
  }
  if (expiresInDays) list[idx].expiresAt = Date.now() + expiresInDays * 24 * 60 * 60 * 1000;
  if (allowEdit !== undefined) list[idx].allowEdit = allowEdit;
  if (questions && Array.isArray(questions) && questions.length > 0) {
    list[idx].questions = questions.map((q, i) => ({
      id: q.id || crypto.randomUUID(),
      type: q.type || "open_ended",
      title: q.title,
      required: q.required !== false,
      order: i,
      options: q.options || [],
      validation: q.validation || "none",
    }));
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

  if (!isSurveyTargeted(survey, decoded.email, user.role)) {
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

  const headers = ["Tarih", "Saat", "Kullanıcı", "Okul"];
  survey.questions.forEach((q) => headers.push(q.title));

  const rows = respList.map((r) => {
    const d = new Date(r.submittedAt);
    const date = d.toLocaleDateString("tr-TR");
    const time = d.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" });
    const schoolName = (users[r.userId]?.profile?.schoolName) || "";
    const row = [date, time, r.userId, schoolName];
    survey.questions.forEach((q) => {
      const ans = r.answers.find((a) => a.questionId === q.id);
      row.push(ans ? `"${(ans.value || "").replace(/"/g, '""')}"` : "");
    });
    return row.join(";");
  });

  const csv = "\uFEFF" + headers.join(";") + "\r\n" + rows.join("\r\n");
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

  const users = loadUsers();
  const respList = loadResponses().filter((r) => r.surveyId === req.params.id);

  const targetUsers = Object.entries(users)
    .filter(([, u]) => {
      if (survey.targetType === "all") return u.role !== "admin";
      if (survey.targetType === "group") return u.role === survey.targetGroup;
      if (survey.targetType === "users") return survey.targetUsers.includes(u.email);
      return false;
    })
    .map(([email, u]) => ({
      email,
      role: u.role,
      schoolName: (u.profile?.schoolName) || "",
      submitted: respList.some((r) => r.userId === email),
      submittedAt: respList.find((r) => r.userId === email)?.submittedAt || null,
    }));

  res.json({ total: targetUsers.length, submitted: respList.length, users: targetUsers });
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
  fs.writeFileSync(FILES_FILE, JSON.stringify({ files: list }, null, 2));
}

function isFileTargeted(file, userEmail, userRole) {
  if (file.targetType === "all") return true;
  if (file.targetType === "group") return file.targetGroup === userRole;
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
    return isFileTargeted(f, decoded.email, activeRole) && (f.startsAt || 0) <= now && f.expiresAt > now;
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
    if (Number(req.body.startsAt) >= Number(req.body.expiresAt)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Baslangic tarihi bitis tarihinden once olmalidir." });
    }
    if (!req.body.targetType) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Hedef kitle zorunlu." });
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
      targetGroup: req.body.targetGroup || null,
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
    if (!isFileTargeted(file, decoded.email, user.role)) {
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

  res.setHeader("Content-Disposition", `attachment; filename="${file.originalName}"`);
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
    .filter(([, u]) => {
      if (file.targetType === "all") return u.role !== "admin";
      if (file.targetType === "group") return u.role === file.targetGroup;
      if (file.targetType === "users") return (file.targetUsers || []).includes(u.email);
      return false;
    })
    .map(([email, u]) => {
      const dl = downloads.find((d) => d.userId === email);
      return {
        email,
        role: u.role,
        schoolName: (u.profile?.schoolName) || "",
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
    .filter(([, u]) => {
      if (file.targetType === "all") return u.role !== "admin";
      if (file.targetType === "group") return u.role === file.targetGroup;
      if (file.targetType === "users") return (file.targetUsers || []).includes(u.email);
      return false;
    })
    .map(([email, u]) => {
      const dl = downloads.find((d) => d.userId === email);
      return {
        email,
        role: u.role,
        schoolName: (u.profile?.schoolName) || "",
        downloaded: !!dl,
        downloadedAt: dl ? dl.downloadedAt : null,
      };
    });

  const csv = "\uFEFF" + ["Kullanici", "Rol", "Okul", "Indirme Durumu", "Indirme Tarihi"].join(";") + "\r\n"
    + targetUsers.map((u) => {
      const status = u.downloaded ? "Indirdi" : "Indirmedi";
      const date = u.downloadedAt ? new Date(u.downloadedAt).toLocaleDateString("tr-TR") + " " + new Date(u.downloadedAt).toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" }) : "";
      return [u.email, u.role, `"${(u.schoolName || "").replace(/"/g, '""')}"`, status, date].join(";");
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
    else if (s.targetType === "group") targetCount = userList.filter((u) => u.role === s.targetGroup).length;
    else if (s.targetType === "users") targetCount = (s.targetUsers || []).length;
    return {
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
      return userList.filter((u) => u.role === a.target).length;
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
    return s + userList.filter((u) => u.role === a.target).length;
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
  fs.writeFileSync(REQUESTS_FILE, JSON.stringify({ requests: list }, null, 2));
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
  if (user.role === "admin") return res.status(403).json({ error: "Admin talep gonderemez." });

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
      return res.status(400).json({ error: "Gecerli bir talep turu secin: talep, oneri, sikayet, itiraz." });
    }
    if (!title || !title.trim()) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Baslik zorunlu." });
    }
    if (!description || !description.trim()) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Aciklama zorunlu." });
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
      submittedAt: Date.now(),
      status: "open",
      responses: [],
      storedName: req.file ? req.file.filename : null,
      originalName: req.file ? req.file.originalname : null,
    };
    list.push(entry);
    saveRequests(list);
    appendLog(makeLog("request_create", decoded.email, `"${entry.title}" talebi olusturuldu (${entry.type}).`, req));
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
    res.setHeader("Content-Disposition", `inline; filename="${entry.originalName}"`);
  } else {
    res.setHeader("Content-Disposition", `attachment; filename="${entry.originalName}"`);
  }
  res.sendFile(filePath);
});

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

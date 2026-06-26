require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

const app = express();

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
const OTP_COOLDOWN_MS = 3 * 60 * 1000;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 3 * 60 * 1000;

const otpStore = new Map();
const lastOtpRequest = new Map();
const failedAttempts = new Map();

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
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Cok fazla istek. Lutfen bekleyin." },
});
app.use(generalLimiter);

const otpSendLimiter = rateLimit({
  windowMs: OTP_COOLDOWN_MS,
  max: 1,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Cok fazla OTP istegi. 3 dakika bekleyin." },
});

const otpVerifyLimiter = rateLimit({
  windowMs: 3 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Cok fazla dogrulama denemesi. Lutfen bekleyin." },
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
    from: `"OTP Girii" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "KOCAELİ ODM OTP Doğrulama Kodu",
    html: `
      <div style="font-family: Arial; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
        <h2 style="color: #333;">KOCAELİ ODM OTP Doğrulama Kodu</h2>
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
  return "admin";
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

  const allAnn = loadAnnouncements();
  const now = Date.now();
  const activeAnn = allAnn.filter((a) => a.expiresAt > now);
  const filteredAnn = activeAnn.filter(
    (a) => a.target === "all" || a.target === role
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

  const common = {
    links: [
      { title: "E-Posta Servisi", url: "#", icon: "fa-envelope", desc: "Kurumsal e-posta yönetimi" },
      { title: "Duyuru Panosu", url: "/navigate/announcements", icon: "fa-bullhorn", desc: "Güncel duyuru ve haberler" },
      { title: "Dosya Yönetimi", url: "#", icon: "fa-folder", desc: "Belge ve dosya paylaşımı" },
      { title: "Takvim", url: "#", icon: "fa-calendar", desc: "Etkinlik ve toplantı takvimi" },
    ],
  };

  const roleData = {
    admin: {
      announcements: filteredAnn,
      links: [
        { title: "Kullanıcı Yönetimi", url: "/navigate/users", icon: "fa-users-gear", desc: "Kullanıcı rollerini yönetin" },
        { title: "Sistem Ayarları", url: "#", icon: "fa-sliders", desc: "Genel sistem yapılandırması" },
        { title: "Log Kayıtları", url: "/navigate/logs", icon: "fa-clipboard-list", desc: "Sistem hareketlerini inceleyin" },
        { title: "Raporlar", url: "#", icon: "fa-chart-bar", desc: "İstatistik ve grafik raporları" },
        ...common.links,
      ],
      stats: [
        { label: "Toplam Kullanıcı", value: String(totalUsers), icon: "fa-users", color: "#6366f1" },
        { label: "Yöneticiler", value: String(adminCount), icon: "fa-user-gear", color: "#22c55e" },
        { label: "Lise Grubu", value: String(liseCount), icon: "fa-school", color: "#f59e0b" },
        { label: "Ortaokul Grubu", value: String(ortaokulCount), icon: "fa-school", color: "#a855f7" },
      ],
    },
    lise: {
      announcements: filteredAnn,
      stats: buildProfileStats(users, email),
    },
    ortaokul: {
      announcements: filteredAnn,
      stats: buildProfileStats(users, email),
    },
  };

  return roleData[role] || roleData.admin;
}

app.post("/api/send-otp", otpSendLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Gecerli bir e-posta adresi girin." });
    }

    const normEmail = email.toLowerCase().trim();
    const now = Date.now();

    const registered = loadUsers();
    if (!registered[normEmail]) {
      return res.status(403).json({ error: "Bu e-posta adresi sistemde kayitli degil. Yetkili kisilerle iletisime gecin." });
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
    appendLog(makeLog("otp_request", normEmail, `${normEmail} adresine OTP gonderildi.`, req));
    res.json({
      message: "OTP kodu e-posta adresinize gonderildi.",
      expiresIn: OTP_EXPIRY_MS,
    });
  } catch (err) {
    console.error("E-posta gonderilemedi:", err.message);
    res.status(500).json({ error: "E-posta gonderilemedi. SMTP ayarlarini kontrol edin." });
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
        error: `Cok fazla basarisiz deneme. ${remaining} saniye bekleyin.`,
        lockout: remaining,
      });
    }
    failedAttempts.delete(normEmail);
  }

  const record = otpStore.get(normEmail);
  if (!record) {
    return res.status(400).json({ error: "Once OTP kodu isteyin." });
  }
  if (now > record.expires) {
    otpStore.delete(normEmail);
    return res.status(400).json({ error: "OTP kodunun suresi doldu. Yeni kod isteyin." });
  }
  if (record.otp !== otp) {
    if (!failData) {
      failedAttempts.set(normEmail, { count: 1, firstAttempt: now });
    } else {
      failData.count += 1;
    }
    return res.status(400).json({ error: "Gecersiz OTP kodu." });
  }

  otpStore.delete(normEmail);
  failedAttempts.delete(normEmail);

  const users = loadUsers();
  if (!users[normEmail]) {
    return res.status(403).json({ error: "Bu e-posta adresi sistemde kayitli degil." });
  }

  users[normEmail].lastLogin = now;
  if (!users[normEmail].role) {
    users[normEmail].role = detectRole(normEmail);
  }
  saveUsers(users);

  const token = jwt.sign({ email: normEmail, role: users[normEmail].role }, JWT_SECRET, { expiresIn: "24h" });
  appendLog(makeLog("login", normEmail, `${normEmail} basariyla giris yapti.`, req));
  res.json({ token, email: normEmail, role: users[normEmail].role });
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
    res.status(401).json({ error: "Gecersiz veya sureci dolmus token." });
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
    return res.status(403).json({ error: "Kullanici bulunamadi." });
  }

  const { schoolName, schoolCode, principalName, principalPhone, schoolPhone, studentCount, teacherCount, classCount } = req.body;
  const autoCode = decoded.email.match(/^(\d+)@meb\.(gov\.tr|k12\.tr)$/);
  users[decoded.email].profile = {
    schoolName: schoolName || "",
    schoolCode: schoolCode || (autoCode ? autoCode[1] : ""),
    principalName: principalName || "",
    principalPhone: principalPhone || "",
    schoolPhone: schoolPhone || "",
    studentCount: studentCount || "",
    teacherCount: teacherCount || "",
    classCount: classCount || "",
  };
  saveUsers(users);
  appendLog(makeLog("profile_update", decoded.email, "Okul bilgileri guncellendi.", req));
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
    const data = getDashboardData(user.role, users, decoded.email);
    res.json({ role: user.role, ...data });
  } catch (_) {
    res.status(401).json({ error: "Gecersiz veya sureci dolmus token." });
  }
});

function authUser(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return null;
  try {
    return jwt.verify(auth.split(" ")[1], JWT_SECRET);
  } catch { return null; }
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
    res.status(403).json({ error: "Bu islem icin admin yetkisi gerekli." });
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
    profile: data.profile || null,
    created: data.created,
    lastLogin: data.lastLogin,
  }));
  res.json(list);
});

app.post("/api/users", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const { email, role } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Gecerli bir e-posta adresi girin." });
  }
  const validRoles = ["admin", "lise", "ortaokul"];
  const userRole = validRoles.includes(role) ? role : detectRole(email);

  const normEmail = email.toLowerCase().trim();
  const users = loadUsers();
  if (users[normEmail]) {
    return res.status(409).json({ error: "Bu e-posta adresi zaten kayitli." });
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
  appendLog(makeLog("user_create", decoded.email, `${normEmail} (${userRole}) kullanici eklendi.`, req));
  res.status(201).json(users[normEmail]);
});

app.put("/api/users/:email", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const normEmail = decodeURIComponent(req.params.email).toLowerCase().trim();
  const users = loadUsers();
  if (!users[normEmail]) {
    return res.status(404).json({ error: "Kullanici bulunamadi." });
  }

  const { role } = req.body;
  const validRoles = ["admin", "lise", "ortaokul"];
  if (role && validRoles.includes(role)) {
    const oldRole = users[normEmail].role;
    users[normEmail].role = role;
    appendLog(makeLog("user_role_change", decoded.email, `${normEmail}: ${oldRole} -> ${role}`, req));
  }
  saveUsers(users);
  res.json(users[normEmail]);
});

app.delete("/api/users/:email", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const normEmail = decodeURIComponent(req.params.email).toLowerCase().trim();
  const users = loadUsers();
  if (!users[normEmail]) {
    return res.status(404).json({ error: "Kullanici bulunamadi." });
  }
  if (normEmail === decoded.email) {
    return res.status(400).json({ error: "Kendinizi silemezsiniz." });
  }

  const deleted = users[normEmail];
  delete users[normEmail];
  saveUsers(users);
  appendLog(makeLog("user_delete", decoded.email, `${normEmail} (${deleted.role}) kullanici silindi.`, req));
  res.json({ message: "Kullanici silindi." });
});

// ---- Announcements ----

app.get("/api/announcements", (req, res) => {
  const decoded = authUser(req);
  if (!decoded) return res.status(401).json({ error: "Token gerekli." });

  const users = loadUsers();
  const user = users[decoded.email];
  if (!user) return res.status(403).json({ error: "Kullanici bulunamadi." });

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
      .filter((a) => a.expiresAt > now && (a.target === "all" || a.target === user.role))
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
    return res.status(400).json({ error: "Baslik, icerik ve hedef kitle gerekli." });
  }
  const validTargets = ["all", "lise", "ortaokul"];
  if (!validTargets.includes(target)) {
    return res.status(400).json({ error: "Gecersiz hedef kitle." });
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
  appendLog(makeLog("announcement_create", decoded.email, `"${title}" duyurusu olusturuldu (hedef: ${target}).`, req));
  res.status(201).json(ann);
});

app.put("/api/announcements/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const list = loadAnnouncements();
  const idx = list.findIndex((a) => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Duyuru bulunamadi." });

  const { title, content, target, expiresInDays } = req.body;
  if (title) list[idx].title = title;
  if (content) list[idx].content = content;
  if (target) {
    const validTargets = ["all", "lise", "ortaokul"];
    if (validTargets.includes(target)) list[idx].target = target;
  }
  if (expiresInDays) {
    list[idx].expiresAt = Date.now() + expiresInDays * 24 * 60 * 60 * 1000;
  }
  saveAnnouncements(list);
  appendLog(makeLog("announcement_edit", decoded.email, `"${list[idx].title}" duyurusu duzenlendi.`, req));
  res.json(list[idx]);
});

app.delete("/api/announcements/:id", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const list = loadAnnouncements();
  const idx = list.findIndex((a) => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Duyuru bulunamadi." });

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
  if (!ann) return res.status(404).json({ error: "Duyuru bulunamadi." });

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
  announcement_create: "Duyuru Oluşturma",
  announcement_edit: "Duyuru Düzenleme",
  announcement_delete: "Duyuru Silme",
  announcement_read: "Duyuru Okuma",
};

app.get("/api/logs", (req, res) => {
  const decoded = requireAdmin(req, res);
  if (!decoded) return;

  const allLogs = loadLogs();
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = Math.min(100, Math.max(10, parseInt(req.query.limit) || 50));
  const start = (page - 1) * limit;
  const total = allLogs.length;

  const list = allLogs.slice(start, start + limit).reverse().map((l) => ({
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
  console.log(`Server http://localhost:${PORT} adresinde calisiyor`);
});

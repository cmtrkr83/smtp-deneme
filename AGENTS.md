# Project Context

## Overview
SMTP tabanlı e-posta ile OTP doğrulama sistemi. Kullanıcılar e-posta + OTP ile giriş yapar. Admin ve kullanıcı (lise/ortaokul/diger) rolleri var. Cross-role geçiş desteklenir.

## Stack
- Backend: Express.js, JWT (jsonwebtoken), Nodemailer, Multer (dosya yükleme), Archiver (ZIP), express-rate-limit
- Frontend: Vanilla HTML+JS, CSS (public/style.css)
- Veri: JSON dosyaları (data/ klasörü altında)

## Critical Config
- JWT secret: `atini-seven-kovboy` (`.env` dosyasında)
- PORT: `4004`
- DATA_DIR: ayarlanmazsa proje kök dizini kullanılır (server.js ve data/ altında users.json var)
- Rate limiter: 15 dk'da 600 istek
- Oturum süresi: admin 1 saat, diğer 30 dk

## Modules & Page Names
| Sidebar label | Page key | API route prefix |
|---|---|---|
| Duyurular | announcements | /api/announcements |
| Anketler | surveys | /api/surveys |
| Dosya Dağıtım | files | /api/files |
| Belge İstekleri | file-requests | /api/file-requests |
| Talep/İtiraz | requests | /api/requests |
| Kullanıcı Yönetimi | users | /api/users |
| Loglar | logs | /api/logs |

## Theme & Colors
- Ana renk: `#8b0000` (koyu kırmızı, logodan alındı)
- Buton/badge kırmızı: `#b91c1c`, `#dc2626`, `#ef4444`
- Hızlı erişim kart renkleri sırasıyla: mavi, yeşil, sarı, mor, pembe, gök mavisi

## Auth & Cross-Roles
- `authUser(req)` → JWT decode eder, null dönerse yetkisiz
- `requireAdmin(req, res)` → admin kontrolü, 401/403 döner
- `resolveRole(user, req)` → `?asRole=` query parametresini okur, kullanıcının `crossRoles` dizisindeki rollere geçişe izin verir
- Tüm fetch çağrılarında `Authorization: Bearer <token>` header'ı zorunlu
- Frontend'de `asRoleQuery()` helper'ı `?asRole=...` string'ini üretir

## Login Flow
1. Kullanıcı e-posta girer + captcha çözer (GET /api/captcha → SVG matematik kodu)
2. POST /api/send-otp → captcha doğrular, OTP gönderir (OTP_COOLDOWN_MS=60000)
3. POST /api/verify-otp → OTP doğrular, JWT döner
4. `login.html` → giriş sayfası
5. Geri tuşu `index.html`'e değil genel bakışa yönlendirir (`location.replace` ile)

## File Upload Rules
- Belge İstekleri: sadece `.zip`, max 10 MB/dosya, max 10 dosya
- Dosya Dağıtım (admin): sadece `.zip`, max 10 MB
- Talep/İtiraz: max 10 MB ek dosya (opsiyonel)

## File Requests (Belge İstekleri)
- Veriler: `data/file-requests.json` (format: `{ requests: [...] }`)
- Yüklemeler: `data/uploads/file-requests/<submissionId>/`
- `loadFileRequests()` → array döndürür (hem dizi hem `{requests: [...]}` formatını destekler)
- `saveFileRequests(list)` → `{ requests: list }` olarak kaydeder
- Token gerekli endpoint'ler (download dahil) fetch ile Authorization header gönderir
- Toplu indirme: GET /api/file-requests/:id/download-all → archiver ile ZIP

## Dashboard Structure (public/dashboard.html)
- `renderDashboard()` → stats + quick access cards + announcements (admin)
- Quick access card'larda highlight flag ile kırmızı arkaplan + pulse animasyonu
- Content area routing: `renderXxx()` fonksiyonları ile sayfalar yönetilir
- Sidebar'da her sayfa `{ page, icon, label, roles }` ile tanımlı

## Data Files
- `data/users.json` - Kullanıcılar
- `data/announcements.json` - Duyurular
- `data/surveys.json` - Anketler
- `data/responses.json` - Anket cevapları
- `data/file-requests.json` - Belge istekleri
- `data/requests.json` - Talep/İtiraz
- `data/logs.json` - Log kayıtları
- `data/files.json` - Dosya dağıtım (eski dosyalarda `startsAt` olmayabilir, `f.startsAt || 0` ile geriye uyumlu)

## Assets
- Logo: `public/assets/logo-kodm.png` (sidebar 64x64, login/index 128x128)
- Favicon: `public/assets/favicon.png`

## Key Implementation Details
- Captcha store: 5 dk TTL, periyodik temizlik, tek kullanımlık (doğru/yanlış farketmeksizin silinir)
- OTP email tasarımı: tablo bazlı HTML, her karakter ayrı kutuda (mavi kenarlıklı)
- Log kayıtları en güncelden en eskiye sıralanır
- Admin file-request detail: email yerine okul adı (userSchool) gösterilir, tek satır kompakt görünüm
- Kullanıcı kartı: bekleyen belge isteği varsa kırmızı arkaplan + pulse animasyonu, yoksa kart gizlenir
- Belge İstekleri ZIP adı: `belge_istegi_<title>.zip`

## Dosyalar
- `server.js` (~2300 satır) - Tüm backend
- `public/dashboard.html` (~3740 satır) - Ana panel (sidebar + tüm sayfalar)
- `public/login.html` - OTP giriş sayfası (captcha)
- `public/index.html` - Karşılama sayfası
- `public/style.css` - Tema ve layout
- `.env` - JWT_SECRET, SMTP ayarları, PORT

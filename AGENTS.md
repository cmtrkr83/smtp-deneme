# Project Context

## Overview
SMTP tabanlı e-posta ile OTP doğrulama sistemi. Kullanıcılar e-posta + OTP ile giriş yapar. Admin ve kullanıcı (lise/ortaokul/diger) rolleri var. Cross-role geçiş desteklenir.

## Stack
- Backend: Express.js, JWT (jsonwebtoken), Nodemailer, Multer (dosya yükleme), Archiver (ZIP), express-rate-limit, helmet, xlsx
- Frontend: Vanilla HTML+JS, CSS (public/style.css)
- Veri: JSON dosyaları (proje kökünde; Docker'da `DATA_DIR=/app/data`)

## Critical Config
- JWT secret: `.env` içindeki `JWT_SECRET` (repo'ya yazma, değer paylaşılma)
- PORT: `4004`
- DATA_DIR: ayarlanmazsa proje kök dizini; Docker compose'ta `/app/data`
- Rate limiter: 15 dk'da 600 istek; send-otp için 15 dk'da 20 istek
- Oturum süresi: admin 1 saat, diğer 30 dk

## Modules & Page Names
| Sidebar label | Page key | API route prefix |
|---|---|---|
| Duyurular | announcements | /api/announcements |
| Anketler | surveys | /api/surveys |
| Dosya Dağıtım | files | /api/files |
| Belge İstekleri | file-requests | /api/file-requests |
| Talep/İtiraz | requests | /api/requests |
| Kullanıcılar | users | /api/users |
| Log Kayıtları | logs | /api/logs |

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
5. Geri tuşu OTP formundan e-posta formuna döner

## File Upload Rules
- Belge İstekleri: sadece `.zip`, max 10 MB/dosya, max 10 dosya
- Dosya Dağıtım (admin): sadece `.zip`, max 10 MB
- Talep/İtiraz: max 10 MB ek dosya (opsiyonel)

## File Requests (Belge İstekleri)
- Veriler: `file-requests.json` (format: `{ requests: [...] }`)
- Yüklemeler: `uploads/file-requests/<submissionId>/`
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
- `users.json` - Kullanıcılar
- `announcements.json` - Duyurular
- `surveys.json` - Anketler
- `responses.json` - Anket cevapları
- `file-requests.json` - Belge istekleri
- `requests.json` - Talep/İtiraz
- `logs.json` - Log kayıtları
- `files.json` - Dosya dağıtım (eski dosyalarda `startsAt` olmayabilir, `f.startsAt || 0` ile geriye uyumlu)

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
- Ek önizlemeler Authorization header ile blob olarak yüklenir (`hydrateAttachments`)

## Deploy (Portainer)
- GitHub → Portainer stack → redeploy canlıya yansır
- `docker-compose`: `DATA_DIR=/app/data`, volume `smtp-data:/app/data`
- Dockerfile image içinde root JSON verilerini `/app/data`'ya kopyalar (ilk volume oluşumunda seed)
- Mevcut boş volume varsa bir kereye mahsus manuel kopya gerekebilir
- nginx `client_max_body_size 12m` (10 MB upload limiti için)

## Dosyalar
- `server.js` (~2400 satır) - Tüm backend
- `public/dashboard.html` (~3800 satır) - Ana panel (sidebar + tüm sayfalar)
- `public/login.html` - OTP giriş sayfası (captcha)
- `public/index.html` - Karşılama sayfası
- `public/style.css` - Tema ve layout
- `.env` - JWT_SECRET, SMTP ayarları, PORT (git'te ignore)

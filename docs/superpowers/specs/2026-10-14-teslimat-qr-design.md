# Fiziki Teslimat (QR Kod) Tasarım Dokümanı (2026-10-14)

Onaylı tasarımın yazılı hali. Kapsam: okullara verilen fiziksel paketlerin 6 haneli kod + karekod ile teslim onayı. Okul giriş yapıp kodu girer/okutur; yönetici teslim durumunu izler + TW-2324 etikete kod basar.

## 1. Amaç ve Kapsam

- Yönetici önceden kod üretir (havuz), pakete atar (kurum seçerek veya paketteki QR'ı okutarak), pakete etiket yapıştırır.
- Okul kullanıcısı giriş yapıp "Fiziki Teslimat" sayfasında kodu yazar veya QR'ı okutur; kod o okula atanmışsa teslim alınmış sayılır.
- Yönetici okul/paket/durum/zamanı izler.
- Kapsam dışı: girişsiz onay (karar: giriş zorunlu), SMS/e-posta bildirimi, kargo firması entegrasyonu, kodun sonradan iptali (kilit + log yeterli).

## 2. Kavramlar ve Durumlar

- Kod: 6 hane, tamamı büyük, harf + rakam; alfabe 32 karakter (A-Z0-9 eksi `0/O/1/I` — elle girişte karışmasın diye; Türkçe harf zaten yok).
- Kod benzersizdir (çakışmada yeniden üretilir).
- Durumlar: `bos` (havuzda) → `atanmis` (okul + paket notu + atanma zamanı) → `teslim_alindi` (zaman + IP + onaylayan e-posta).
- Geçerlilik: onaylanana kadar süresiz; onayda tek kullanımlık ölür.
- Yanlış deneme: okul/IP başına 5 yanlışta 15 dk kilit + log.

## 3. Veri Modeli

Dosya: `deliveries.json` → `{ codes: [...] }` (proje JSON kuralına uygun).

Kayıt: `{ code, status, schoolEmail, note, createdAt, assignedAt, confirmedAt, confirmedBy, confirmIp, failCount, lockedUntil }`
- Yazma her zaman `atomicSaveJson()` ile.
- Mevcut hiçbir JSON dosyasının şemasına alan eklenmez.

## 4. API

| Yöntem | Route | Yetki |
|---|---|---|
| POST | `/api/deliveries/generate` | admin (`count`, en fazla 500) |
| GET | `/api/deliveries/pool` | admin (`status=bos`, varsayılan 200 kayıt limitli) |
| POST | `/api/deliveries/assign` | admin (`code`, `schoolEmail`, opsiyonel `note`) |
| GET | `/api/deliveries/mine` | token'lı okul (atanmış + onaylanmış paketleri) |
| POST | `/api/deliveries/confirm` | token'lı okul (`code`) — kod bu okula atanmışsa kabul |
| GET | `/api/deliveries` | admin (izleme listesi: okul, not, durum, zamanlar) |
| GET | `/api/deliveries/print?codes=A,B,...` | admin (etiket baskı verisi: kod + QR data-URL) |

- Doğrulama: kod formatı `^[A-HJ-NP-Z2-9]{6}$` (32'li alfabe; dışında kalan `0/O/1/I` girilirse 400); başkasının koduysa "bu kod size atanmadı" (403); kilitliyken 429.
- Hız sınırı: confirm `15 dk/20` (send-otp deseni); diğerleri genel limit.
- Yazma işlemleri `logs.json`'a `delivery_generate` / `delivery_assign` / `delivery_confirm` / `delivery_fail` / `delivery_lock` olarak işlenir.
- QR içeriği: mutlak URL `<PUBLIC_BASE_URL>/dashboard.html?teslimat=KOD` (`PUBLIC_BASE_URL` yoksa istek host'undan türetilir; `.env`'e girer, repoya yazılmaz).

## 5. Arayüz

- **Sidebar:** okul rollerine "Fiziki Teslimat" (`fa-box-open`), admin'e "Teslimatlar" (`fa-boxes-packing`). Mevcut sayfalar değişmez.
- **Okul sayfası:** bekleyen paketler listesi + kod girişi (elle) + "Kamerayla Okut" (telefon kamerası URL'yi açar, kod alana dolar) + "Teslim Aldım". Başarıda rozet/vurgu söner (mevcut highlight deseni).
- **Admin:** havuz görünümü (boş kodlar + toplu üret + yazdır seçimi), eşleştirme (kurum seç + kod ata veya QR okut), izleme tablosu.
- **Giriş akışı:** QR girişsiz açılırsa `login.html?next=` ile giriş sonrası teslimat sayfasına dönülür (`next` yoksa davranış aynı). `dashboard.html?teslimat=KOD` parametresi sayfayı kod dolu açar.
- Tema değişkenleri (`var(--...)`) kullanılır; tarih gösterimi mevcut `DD-MM-YYYY` kuralında.

## 6. Etiket Baskısı (TW-2324)

- Şablon: Tanex TW-2324, 70×35 mm, A4'te 3 sütun × 8 satır = 24 etiket.
- Baskı görünümü: sayfa başına 24 hücre (mm ölçü birebir), hücrede QR + altında 6 haneli kod iri + minik "Fiziki Teslimat" başlığı. `@page A4`, uygulama menüleri baskıda gizli (`window.print`).
- QR üretimi sunucuda `qrcode` npm paketiyle (istemcide ek bağımlılık yok, çevrimdışı çalışır).
- Yalnızca `bos` kodlar basılabilir; baskı durumu değiştirmez (tüketim atamada olur).

## 7. Yedekleme

- `BACKUP_SECTIONS`'a `deliveries` eklenir (eklemeli değişiklik): `deliveries.json` yedeğe girer/geri yüklenir. `.env` girmez.

## 8. Test

- Backend (`node --test test/`, yeni dosya): tokensiz yazma 401, non-admin admin route'larında 403, alfabe/uzunluk/benzersizlik, ata→onayla akışı, başkasının kodu 403, 5 yanlışta kilit, onayda tek kullanımlık ölüm.
- Frontend: baskı şablonu 24/sayfa hesabı + JS sözdizimi kontrolü.

## 9. İzolasyon (var olan sisteme dokunulmaz)

- Değişmeyenler: mevcut JSON şemaları, mevcut API route'ları ve davranışları, mevcut sayfalar, login akışı (`next` yoksa birebir aynı), rozet/highlight mantığı (sadece yeni sayfa kullanır).
- Yeni eklenenler: `deliveries.json`, `/api/deliveries*` route'ları, iki sidebar sayfası, `qrcode` bağımlılığı, `PUBLIC_BASE_URL` (opsiyonel `.env`), `test/deliveries.test.js`.

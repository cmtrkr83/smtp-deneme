# Takvim Tasarım Dokümanı (2026-10-12)

Onaylı tasarımın yazılı hali. Kapsam: Genel Bakış'ta %50 takvim kutusu + herkese açık etkinlikler + kutudan yönetim.

## 1. Amaç ve Kapsam

- Genel Bakış sayfası iki sütun olur: sol %50 Hızlı Erişim, sağ %50 Takvim (mobilde alt alta).
- Takvim tüm rollerde görünür; etkinlikler herkese açıktır (hedefleme yok).
- Yönetici etkinlik ekler/düzenler/siler; işlem yeri yalnızca takvim kutusudur (ayrı sayfa yok).
- Kapsam dışı: saat bilgisi, tekrarlayan etkinlik, hatırlatma bildirimi.

## 2. Veri Modeli

Dosya: `events.json` → `{ events: [...] }` (proje JSON kuralına uygun).

Kayıt: `{ id, title, description, startDate, endDate, createdAt }`
- `startDate`/`endDate`: saklamada `YYYY-MM-DD` (sıralama + `<input type="date">` uyumu), ekranda her zaman `DD-MM-YYYY` (örn. 12-10-2026).
- Yazma her zaman `atomicSaveJson()` ile.

## 3. API

| Yöntem | Route | Yetki |
|---|---|---|
| GET | `/api/events` | token'lı herkes (tarihe göre artan sıralı) |
| POST | `/api/events` | admin (`title`, `startDate`, opsiyonel `endDate`, `description`) |
| PUT | `/api/events/:id` | admin (aynı alanlar) |
| DELETE | `/api/events/:id` | admin |

- Doğrulama: başlık zorunlu; tarih formatı `YYYY-MM-DD`; `endDate < startDate` ise 400.
- Yazma işlemleri `logs.json`'a `event_add` / `event_update` / `event_delete` olarak işlenir.

## 4. Arayüz

- **Kutu:** ay ızgarası (hafta başı Pazartesi), ay ileri/geri + Bugün düğmesi, bugün vurgulu. Referans görseldeki minimal çizgi esas alınır: başlık + kare gezgin düğmeler, seçili gün marka kırmızısı yuvarlak-kare + gölge, komşu ay günleri sönük.
- **İşaretleme:** etkinlikli günlerde renkli nokta + gün arkaplanı; çok günlük etkinlik aralığın her gününü boyar.
- **Popup:** hover / odak / dokunma ile açılır; başlık + tarih aralığı + açıklama. `tabindex` + `focus-within` ile klavye erişilebilir.
- **Admin:** kutu başlığında `+ Ekle` (modal: başlık, başlangıç/bitiş, açıklama); kutu altı "Yaklaşanlar" listesinde satır başına düzenle/sil (liste tüm rollerde görünür, ikonlar sadece adminde). Yaklaşanlar: bitmemiş etkinliklerden ilk 3 (tarihe göre).
- **Yerleşim:** `.overview-split { grid-template-columns: 1fr 1fr; }`, 900px altında tek sütun. Tema değişkenleri (`var(--...)`) kullanılır, sabit renk yok.

## 5. Test

- Backend (`node --test test/`): tokensiz yazma 401, non-admin yazma 403, CRUD + sıralama + tarih doğrulama.
- Frontend: headless ekran görüntüsü (kutu, popup, admin ikonları), JS sözdizimi kontrolü.

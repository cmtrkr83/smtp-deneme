# Fiziki Teslimat (QR Kod) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Okullara verilen fiziksel paketlerin 6 haneli kod + karekod ile teslim onayını sisteme eklemek, var olan sistemi değiştirmeden.

**Architecture:** Yeni `deliveries.json` dosyası + `/api/deliveries*` route'ları + iki sidebar sayfası (okul: Fiziki Teslimat, admin: Teslimatlar). QR sunucuda `qrcode` paketiyle üretilir. Mevcut dosyalara yalnızca eklemeli dokunuşlar (sidebar girdisi, BACKUP_SECTIONS girdisi, login `next` parametresi).

**Tech Stack:** Node.js (Express 4), `qrcode@^1.5.4` (yeni bağımlılık), vanilla JS, `node --test`.

**Spec:** `docs/superpowers/specs/2026-10-14-teslimat-qr-design.md`

## Global Constraints

- JSON yazma her zaman `atomicSaveJson()` ile (tmp + rename); ham `writeFileSync` yasak (test seed'i hariç).
- Kod alfabesi 32 karakter: `A-HJ-NP-Z2-9` (büyük, Türkçe harf yok, `0/O/1/I` yok); 6 hane; benzersiz.
- Kod format regex: `^[A-HJ-NP-Z2-9]{6}$`.
- Tarih gösterimi `DD-MM-YYYY`; görünen metinlerde düzgün Türkçe karakterler.
- Tema renkleri `var(--...)` ile; hardcoded hex yok (marka butonlarındaki `#fff` hariç).
- Commit mesajları repo stili: `feat:` / `fix:` / `docs:` + Türkçe açıklama.
- Rate limit: confirm `15 dk/20` (send-otp deseni), diğerleri genel limit.
- Her task sonunda ilgili testler yeşil; son taskta tüm süit yeşil.

## Review Focus

- `0/O/1/I` içeren kod girilirse 400 dönmeli, alfabetik yakınlık affedilmemeli (örn. `0` yazan `O` olarak kabul edilmemeli).
- Başka okula atanmış kodla onay denenirse 403 + "bu kod size atanmadı" dönmeli, fail sayacı artmamalı.
- 5 yanlış sonrası 15 dk kilit bitmeden doğru kod bile kabul edilmemeli.
- Onaylanan kod ikinci kez kullanılamamalı (tek kullanımlık ölüm).
- Baskı görünümü sayfa başına tam 24 etiket dizmeli (3×8), 25. kod ikinci sayfaya taşmalı.

---

### Task 1: Kod havuzu backend (generate/pool/assign)

**Files:**
- Modify: `server.js` (helpers + 3 route, `~loadFileRequests` civarına ekle)
- Test: `test/deliveries.test.js` (yeni)

**Interfaces:**
- Consumes: `atomicSaveJson` (`server.js:71`), `requireAdmin` (`server.js:786`), `loadUsers`, `appendLog`/`makeLog`, `actionLabels` (yeni anahtarlar `delivery_generate`, `delivery_assign` Türkçe etiketlerle).
- Produces: `loadDeliveries() -> { codes: [] }` (dosya yoksa `{ codes: [] }` döner); `DELIVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"`; route'lar `POST /api/deliveries/generate`, `GET /api/deliveries/pool`, `POST /api/deliveries/assign`.

- [ ] **Step 1: Write the failing test**

```js
// test/deliveries.test.js (port 4110, helpers.startServer/adminToken kullanır)
test("admin 10 kod uretir (alfabe + benzersizlik)", async () => {
  const r = await fetch(srv.base + "/api/deliveries/generate", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken() },
    body: JSON.stringify({ count: 10 }),
  });
  assert.equal(r.status, 200);
  const data = await r.json();
  assert.equal(data.codes.length, 10);
  assert.ok(data.codes.every((c) => /^[A-HJ-NP-Z2-9]{6}$/.test(c)));
  assert.equal(new Set(data.codes).size, 10);
});
test("tokensiz generate 401, non-admin 403", async () => { /* ... */ });
test("assign bos kodu okula baglar", async () => {
  // POST /api/deliveries/assign { code, schoolEmail: "kullanici@test.local", note: "LGS" } -> 200, status atanmis
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/deliveries.test.js`
Expected: FAIL (route'lar yok → 404)

- [ ] **Step 3: Implement helpers + 3 route in `server.js`**

`DELIVERIES_FILE`, `loadDeliveries`/`saveDeliveries` (eksik dosyada `{ codes: [] }`); kayıt `{ code, status: "bos", schoolEmail: null, note: "", createdAt, assignedAt: null, confirmedAt: null, confirmedBy: null, confirmIp: null, failCount: 0, lockedUntil: 0 }`; generate `count` 1–500 doğrular; pool varsayılan 200 kayıt limitli; assign yalnızca `bos` kodu `atanmis` yapar (okul `users.json`'da olmalı, yoksa 404).

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/deliveries.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.js test/deliveries.test.js
git commit -m "feat: teslimat kod havuzu API (generate/pool/assign)"
```

### Task 2: Onay + kilit + listeleme backend

**Files:**
- Modify: `server.js` (3 route + `actionLabels`: `delivery_confirm`, `delivery_fail`, `delivery_lock`)
- Test: `test/deliveries.test.js` (ekle)

**Interfaces:**
- Consumes: Task 1 (`loadDeliveries`, `saveDeliveries`).
- Produces: `GET /api/deliveries/mine` (okul: atanmış + onaylanmışları), `POST /api/deliveries/confirm` (okul), `GET /api/deliveries` (admin izleme).

- [ ] **Step 1: Write the failing tests**

```js
test("okul kendine atanmis kodu onaylar", async () => {
  // assign -> confirm { code } (userToken) -> 200; ikinci confirm 410/400 (tek kullanimlik olum)
});
test("baskasinin kodu 403 + fail sayaci artmaz", async () => { /* ... */ });
test("alfabe disi kod 400", async () => {
  // confirm { code: "00II11" } -> 400
});
test("5 yanlisda 15 dk kilit", async () => {
  // atanmamis/yanlis 6 haneli kodla 5 kez -> 6. deneme (dogru kod bile olsa) 429
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/deliveries.test.js`
Expected: FAIL (route'lar yok)

- [ ] **Step 3: Implement 3 route in `server.js`**

confirm sırası: format 400 → kilit kontrolü 429 (`lockedUntil > now`, okul+IP anahtarlı sayaç) → kod yoksa fail++ ve 404 → başkasına atanmışsa 403 (sayaç artmaz) → kendine atanmışsa `teslim_alindi` + sayaç sıfırla. `mine`: yalnızca kendi `schoolEmail` kayıtları.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/deliveries.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.js test/deliveries.test.js
git commit -m "feat: teslimat onay + kilit + listeleme API"
```

### Task 3: QR + etiket baskı verisi

**Files:**
- Modify: `server.js` (`GET /api/deliveries/print`), `package.json` + `package-lock.json` (`qrcode@^1.5.4`)
- Test: `test/deliveries.test.js` (ekle)

**Interfaces:**
- Consumes: Task 1 (`loadDeliveries`).
- Produces: `GET /api/deliveries/print?codes=A,B,...` → `{ items: [{ code, qr }] }` (`qr`: PNG data-URL; QR içeriği `<baz>/dashboard.html?teslimat=KOD`, baz `process.env.PUBLIC_BASE_URL` yoksa istek host'undan).

- [ ] **Step 1: Write the failing test**

```js
test("print yalniz bos kodlari QR ile doner", async () => {
  // generate 3 -> print?codes=... -> 200, her item.data-URL `data:image/png;base64,` ile baslar
  // atanmis kod istenirse listede olmaz
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm install qrcode@^1.5.4` önce (kurulum Task 3'e dahil), sonra `node --test test/deliveries.test.js`
Expected: FAIL

- [ ] **Step 3: Implement route in `server.js`**

`require("qrcode").toDataURL(url, { width: 200, margin: 1 })`; yalnızca `status === "bos"` kodlar; en fazla 48 kod/sayfa çağrısı (2 sayfa).

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/deliveries.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.js package.json package-lock.json test/deliveries.test.js
git commit -m "feat: teslimat QR + etiket baski verisi"
```

### Task 4: Okul "Fiziki Teslimat" sayfası

**Files:**
- Modify: `public/dashboard.html` (sidebar girdisi `lise/ortaokul/diger` + `renderDeliveries()`)
- Test: önizleme dizesi + JS sözdizimi kontrolü (aşağıda)

**Interfaces:**
- Consumes: Task 2 (`GET /api/deliveries/mine`, `POST /api/deliveries/confirm`).
- Produces: sidebar `{ page: "deliveries", icon: "fa-box-open", label: "Fiziki Teslimat", roles: ["lise", "ortaokul", "diger"] }`; bekleyen paket + kod girişi + "Teslim Aldım"; başarıda dashboard highlight sönmesi için `refreshDashboardData()` çağrısı; `?teslimat=KOD` ile açılışta kodun alana dolması (Task 5'teki yönlendirme buraya düşer).

- [ ] **Step 1: Write the failing check**

```js
// node one-liner: sidebar girdisi + renderDeliveries mevcut mu?
```

- [ ] **Step 2: Run check to verify it fails**

Expected: FAIL (0 eşleşme)

- [ ] **Step 3: Implement**

Okul sayfası `report-card` stilinde; kod inputu otomatik büyük harf + alfabe dışı karakter temizliği (client-side); hata metinleri Türkçe (`Bu kod size atanmadı.` vb.).

- [ ] **Step 4: Run check + syntax to verify**

Run: yukarıdaki check (PASS) + inline `<script>` bloklarını `/tmp`'ye çıkarıp `node --check`
Expected: PASS + SYNTAX-OK

- [ ] **Step 5: Commit**

```bash
git add public/dashboard.html
git commit -m "feat: okul fiziki teslimat sayfasi"
```

### Task 5: Giriş akışı (`?next=` + `?teslimat=`)

**Files:**
- Modify: `public/login.html` (`?next=` dönüşü), `public/dashboard.html` (`dashboard.html?teslimat=KOD` karşılama)
- Test: önizleme dizesi + JS sözdizimi kontrolü (aşağıda)

**Interfaces:**
- Consumes: Task 4 (kod dolu açılabilen teslimat sayfası).
- Produces: `login.html`: `verify-otp` başarısında `?next=` varsa oraya (yalnızca `/dashboard.html` ile başlayan göreli yol, açık yönlendirme yok), yoksa `/dashboard.html`. Dashboard `init`: `?teslimat=KOD` varsa giriş sonrası deliveries sayfasını kod dolu açar.

- [ ] **Step 1: Write the failing check**

```js
// node one-liner: ?next + ?teslimat karşılama mevcut mu?
```

- [ ] **Step 2: Run check to verify it fails**

Expected: FAIL (0 eşleşme)

- [ ] **Step 3: Implement**

Yukarıdaki Interfaces aynen uygulanır; `next` yoksa davranış birebir aynı kalır.

- [ ] **Step 4: Run check + syntax to verify**

Run: yukarıdaki check (PASS) + inline `<script>` bloklarını `/tmp`'ye çıkarıp `node --check`
Expected: PASS + SYNTAX-OK

- [ ] **Step 5: Commit**

```bash
git add public/dashboard.html public/login.html
git commit -m "feat: teslimat giris akisi (next + teslimat param)"
```

### Task 6: Admin "Teslimatlar" (havuz/eşleştirme/izleme/baskı)

**Files:**
- Modify: `public/dashboard.html` (sidebar girdisi admin + `renderAdminDeliveries()` + baskı görünümü `@page A4`, 70×35mm hücre)
- Test: 24/sayfa hesabı + JS sözdizimi kontrolü

**Interfaces:**
- Consumes: Task 1–3 route'ları.
- Produces: sidebar `{ page: "admin-deliveries", icon: "fa-boxes-packing", label: "Teslimatlar", roles: ["admin"] }`; havuz (üret + yazdır seçimi), eşleştirme (kurum seç + kod ata / QR okut), izleme tablosu (okul, not, durum, zamanlar).

- [ ] **Step 1: Write the failing check**

```js
// 25 kodluk listede baski HTML'i 2 sayfa (48 hucre) uretmeli; 24 kod tek sayfa
```

- [ ] **Step 2: Run check to verify it fails**

Expected: FAIL

- [ ] **Step 3: Implement**

Baskı: `window.print` + yalnızca baskı görünümü (`@media print` ile uygulama chrome'u gizli); hücre `70mm × 35mm` sabit; QR `<img>` + kod iri + "Fiziki Teslimat" minik. Eşleştirmede QR okutma: telefon kamerası URL'yi açar, kod alana dolar (ek kütüphane yok).

- [ ] **Step 4: Run check + syntax to verify**

Expected: PASS + SYNTAX-OK

- [ ] **Step 5: Commit**

```bash
git add public/dashboard.html
git commit -m "feat: admin teslimatlar havuz/eslestirme/izleme/baski"
```

### Task 7: Yedekleme + tam regresyon

**Files:**
- Modify: `server.js` (`BACKUP_SECTIONS` + `deliveries` girdisi), `test/helpers.js` (seed'e `deliveries.json`)
- Test: tüm süit

**Interfaces:**
- Consumes: Task 1 (`deliveries.json` formatı).
- Produces: `deliveries: { label: "Teslimatlar", files: ["deliveries.json"], uploadSubdirs: [] }`.

- [ ] **Step 1: Write the failing test**

```js
// test/deliveries.test.js'e ekle: POST /api/backup { sections: ["deliveries"] } zip içerir deliveries.json
```

Mevcut backup test deseni (`test/restore-guards.test.js`) referans alınır.

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/deliveries.test.js`
Expected: FAIL

- [ ] **Step 3: Implement BACKUP_SECTIONS girdisi + helpers seed'i**

- [ ] **Step 4: Run full suite**

Run: `npm test`
Expected: 22 + yeni testler, hepsi PASS

- [ ] **Step 5: Commit**

```bash
git add server.js test/helpers.js test/deliveries.test.js
git commit -m "feat: teslimatlar yedekleme + tam regresyon"
```

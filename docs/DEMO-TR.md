# DAST Tool: yerel demo ve çalışma rehberi

Bu rehber `feat/passive-dast-mvp` dalındaki sürüm içindir; PR henüz main'e
birleştirilmediyse doğrudan bu dalı kullan.

## 1. Kurulum — Windows PowerShell

Python 3.11 veya üzeri ve Git kurulu olmalı:

```powershell
git clone --branch feat/passive-dast-mvp https://github.com/egekarakaya/DAST-Tool.git
cd DAST-Tool
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

Sanal ortamı aktive etmek zorunda değilsin; aşağıdaki komutlar doğrudan ortamın
Python'unu kullanır. Paket kurulunca ortam içinde `dast` CLI komutu da oluşur.

## 2. Demo uygulama — birinci terminal

Aynı repo klasöründe:

```powershell
.\.venv\Scripts\python.exe examples/dummy_app.py --port 8080 --mode vulnerable
```

Tarayıcıda `http://127.0.0.1:8080` adresini açabilirsin.
Sunucu sadece 127.0.0.1'e bağlanır; tüm kayıtlar ve tokenlar sentetiktir.
Demo gerçek hesaplara, diskteki verilere veya harici servislere bağlanmaz.
Sayfadaki örnek dış script adresi geçersiz .invalid alan adıdır; scanner onu indirmez.

## 3. Pasif tarama — ikinci terminal

İkinci PowerShell terminalini aynı DAST-Tool klasöründe aç:

```powershell
.\.venv\Scripts\python.exe -m dast.cli scan http://127.0.0.1:8080 --profile production --rps 2 --output reports/passive
Start-Process reports/passive/report.html
```

Tarayıcı tıklamaları gerekmez. Araç ana sayfayı GET ile alır, HTML bağlantılarını
çıkarır ve aynı origin içindeki izinli URL'leri ziyaret eder. Üretim profilinde
query string içeren adresler atlanır. Formlar gönderilmez.
CSP/cookie, hata sızıntısı, dizin listesi, password formu gibi pasif bulgular beklenir.
Bu komut injection testi veya rol karşılaştırması yapmaz.

## 4. OWASP odaklı kontrollü tarama

İkinci terminalde demo admin rolünü tanımla ve aktif kontrolleri aç:

```powershell
$env:DAST_DEMO_ADMIN = "Bearer demo-admin"
.\.venv\Scripts\python.exe -m dast.cli scan http://127.0.0.1:8080 --profile standard --active --rps 5 --max-requests 150 --auth-config examples/demo-auth.json --access-policy examples/demo-access.json --output reports/vulnerable
Start-Process reports/vulnerable/report.html
```

`demo-admin` yalnızca eğitim uygulamasına ait sabit, sentetik bir değerdir.
Gerçek taramalarda tokenları repoya yazmadan ortam değişkenleriyle ver.

Beklenen örnekler:

| Endpoint | Bulgu | Ne kanıtlıyor? |
|---|---|---|
| /admin | access-policy-violation — A01 | Admin'e özel olarak tanımladığımız içerik anonim rolde de dönüyor. |
| /item?id=1 | sql-error-differential — A05 | Tek tırnak yeni SQL hata imzası üretiyor; baseline/kontrol üretmiyor. SQLi için inceleme gerekli. |
| /search?q=hello | html-injection — A05 | Zararsız bir HTML etiketi encode edilmeden dönüyor. JavaScript/XSS çalıştırıldığı anlamına gelmez. |
| /login | password-over-http, password-in-get-form — A04 | Form yapılandırması credential aktarımı açısından güvensiz. Form gönderilmedi. |
| /errors | error-disclosure — A02/A10 | Yanıt gövdesinde traceback imzası görüldü. |
| /files/ | directory-listing — A02 | Dizin başlığı, heading ve linkler bir arada. |
| / | session-in-link — A07 | Linkte session identifier adı var; değeri raporda gizli. |
| / | external-script-no-sri — A08 | Dış script için integrity bilgisi eksik; tedarik zinciri saldırısı kanıtı değil. |

## 5. Düzeltilmiş uygulamayla karşılaştır

Birinci terminalde Ctrl+C ile uygulamayı durdur, sonra:

```powershell
.\.venv\Scripts\python.exe examples/dummy_app.py --port 8080 --mode fixed
```

İkinci terminalde aynı kontrolleri yeni rapor klasörüne çalıştır:

```powershell
.\.venv\Scripts\python.exe -m dast.cli scan http://127.0.0.1:8080 --profile standard --active --rps 5 --max-requests 150 --auth-config examples/demo-auth.json --access-policy examples/demo-access.json --output reports/fixed
Start-Process reports/fixed/report.html
```

Fixed mod, SQL parametreleme ve HTML encoding uygular, /admin için token kontrol
eder, ayrıntılı hataları/dizin listesini kaldırır ve güvenlik başlıklarını ekler.
Login formunu da HTTP üzerinden credential toplamayan açıklama sayfasına çevirir.
Bu demo için hedeflenen bulguların kaybolması ve anonim /admin erişiminin
`denied-as-expected` olması beklenir. Bu sonuç uygulamanın tüm OWASP risklerinden
arınmış olduğu anlamına gelmez; test edilmeyen alanlar raporda görünür.

## 6. Araç nasıl çalışıyor?

`CLI/config -> Policy -> Transport -> Crawling -> Assessment -> Reporting`

1. **Policy:** origin, rol path kapsamı, profil ve bütçeleri uygular.
2. **Transport:** HTTP/1.0–2, TLS, cookie oturumları, sıkıştırma, hız ve timeout.
3. **Crawling:** bağlantıları kuyruğa alır; OpenAPI JSON'dan GET URL'leri de alabilir.
4. **Assessment:** pasif kurallar her yanıtı inceler. Aktif seçenek açılırsa kontrol
   ve probe istekleri aynı bütçeden harcanır. Roller arası erişim karşılaştırılır.
5. **Reporting:** bulgular ve OWASP/CWE eşleştirmesi JSON ve HTML'e yazılır.
   `confidence` kanıt türünü, `request_kind` baseline/control/probe ayrımını gösterir.
   `stop_reason` taramanın tamamlandığını veya neden durduğunu belirtir.

Tek endpoint / manuel mod:

```powershell
.\.venv\Scripts\python.exe -m dast.cli scan "http://127.0.0.1:8080/search?q=hello" --profile standard --active --no-crawl --output reports/manual
```

API keşfi:

```powershell
.\.venv\Scripts\python.exe -m dast.cli scan http://127.0.0.1:8080 --openapi examples/openapi.json --output reports/api
```

Varsayılan profil 1 istek/saniye, 50 istek ve 120 saniye bütçe kullanır.
`--rps`, `--max-requests`, `--max-depth`, `--max-seconds` ile ayarlanabilir.
Üretim profilinin tavanı 2 rps/200 istektir. Aktif probe üretim profilinde reddedilir.

Çıkış kodları: **0** tamamlandı ve eşik aşılmadı; **1** `--fail-on` eşiğinde bulgu;
**2** yapılandırma, bağlantı, sağlık veya bütçe nedeniyle eksik tarama.
Varsayılan `--fail-on none` nedeniyle bulgu olsa bile başarılı tarama 0 dönebilir.

## Kapsam sınırları

[OWASP matrisi](OWASP-2025.md) tüm kategorileri ve sınırları listeler.
A03 tedarik zinciri, A06 tasarım ve A09 log/alert doğrulaması bu sürümde test edilmez.
Tarayıcı JS çalıştırma, otomatik login, POST form gönderimi ve kapsamlı API fuzzing yok.
GET istekleri de kötü tasarlanmış uygulamalarda yan etki yaratabilir; aktif profili
önce bu yerel lab ve yetkili staging ortamında kullan.

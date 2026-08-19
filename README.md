# Oxysintx — Security Testing & OSINT Dashboard

Dashboard peribadi untuk security testing pasif dan OSINT ke atas domain yang
anda **miliki atau ada kebenaran bertulis untuk diuji**.

## Ciri-ciri

- Login username + password, dengan **role** (Owner / Analyst / Viewer) —
  tiada pendaftaran akaun awam. Akaun `Yanxzyx` (role Owner) dicipta
  automatik oleh `app.py` pada kali pertama dijalankan, password
  dipaparkan sekali di console
- **Settings (Owner sahaja):** create akaun baru — kena pilih role dahulu,
  password dijana automatik dan dipaparkan sekali sahaja; senarai semua
  akaun; padam akaun (tak boleh padam Owner terakhir yang tinggal)
- **Role Analyst** — akses penuh ke semua tools, tapi tiada akses Settings
- **Role Viewer** — read-only: boleh tengok History/Docs/hasil scan, tapi
  butang Start Scan / Quick Scan / delete / AI Chat send-clear disekat
  (server-side, bukan sekadar sorok UI)
- `login.html` dan `dashboard.html` kini **self-contained** — semua CSS/JS
  kepunyaan projek ini di-inline terus dalam fail HTML (tiada fail
  `static/css` atau `static/js` berasingan lagi). Backend (`app.py`,
  `modules/`, dll.) kekal modular/berasingan seperti asal.
- Tema merah-hitam, mod gelap/terang, animasi halus, ikon Font Awesome,
  tiada emoji
- 10 recon/security tool (mod Basic & Expert): WHOIS, DNS, SSL/TLS, HTTP
  Security Headers, Subdomain Discovery, Tech Fingerprint, IP/ASN Info,
  Email Security (SPF/DKIM/DMARC), Port Scan, Connectivity Check
- Overview: Quick Scan + senarai Recent Scans terus di halaman utama
- History: carian/filter ikut target, muat turun (download) hasil sebagai
  JSON, boleh padam setiap entry
- Console server (log tail) + monitor CPU/RAM/Disk secara live
- Code/text viewer dengan syntax highlighting gaya VS Code (highlight.js),
  extract & klik terus script/CSS/image link dari HTML yang di-fetch
- AI Chat (guna Anthropic API key anda sendiri, model `claude-sonnet-5`) —
  boleh padam sejarah chat
- Dokumentasi terperinci — 6 kategori, setiap tool dijelaskan (apa, kenapa,
  macam mana baca hasil), plus bahagian konsep keselamatan
- Toast notification, mobile-responsive (hamburger menu), skeleton loading
- Backend seni bina modular/plugin — tambah tool baru sekadar letak fail
  dalam folder `modules/`

## Apa yang SENGAJA tidak dimasukkan

- **Proxy scraper / proxy rotation** — boleh disalahguna untuk elak
  rate-limit/IP-ban semasa scan besar-besaran ke website lain
- **Cloudflare real-IP / bypass proteksi** — untuk serang origin server terus
- **Brute force** (login/password)
- **Upload & jalankan sebarang fail Python** sebagai ciri terbuka — risiko
  *arbitrary code execution*. Sebagai ganti, gunakan seni bina plugin di
  `modules/` untuk tambah tool anda sendiri yang telah disemak
- **Pendaftaran akaun awam / pelan berbayar untuk orang luar** — Settings
  di sini untuk pemilik urus akaun pasukan sendiri, bukan platform terbuka

Semua tool yang dibina bersifat **pasif/read-only** — ia hanya membaca
maklumat awam (sama seperti securityheaders.com, crt.sh, atau arahan
`whois`), tiada exploit dihantar.

## Pasang & Jalankan

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# (pilihan) untuk AI Chat, salin .env.example -> .env dan isi ANTHROPIC_API_KEY
cp .env.example .env

python app.py
```

Kali pertama dijalankan, akaun `Yanxzyx` (role **Owner**) akan dicipta
automatik dan password dipaparkan di terminal — **simpan password ini**, ia
tidak dipaparkan semula. Untuk jana password baru untuk akaun ini pada bila-
bila masa (role dikekalkan):

```bash
python app.py reset-password
```

Buka `http://localhost:5000`, log masuk dengan username `Yanxzyx` dan
password tersebut. Startup log juga akan bagitahu jika ada tool yang gagal
loaded (biasanya bermakna `pip install` tak lengkap).

## Role & Settings

| Role    | Tools (scan/history/chat) | Delete/Clear | Settings |
|---------|:--------------------------:|:------------:|:--------:|
| Owner   | ✔                          | ✔            | ✔        |
| Analyst | ✔                          | ✔            | ✘        |
| Viewer  | lihat sahaja                | ✘            | ✘        |

Sebagai Owner, pergi ke **Settings** untuk create akaun baru: masukkan
username, **pilih role dahulu**, submit — username + password baru terus
dipaparkan (sekali sahaja, tiada cara lihat semula password lama). Owner
terakhir yang tinggal tidak boleh dipadam, supaya anda tak boleh terkunci
keluar sepenuhnya.

## Tambah Tool Sendiri

Cipta fail baru dalam `modules/`, contohnya `modules/my_tool.py`:

```python
TOOL_INFO = {"name": "My Tool", "description": "Penjelasan ringkas."}

def run(target: str, mode: str = "basic") -> dict:
    # logik anda di sini (mode: "basic" atau "expert")
    return {"tool": "my_tool", "target": target, "data": {}, "error": None}
```

Tool akan auto-detect dan terus muncul dalam senarai di dashboard — tiada
perlu edit `app.py` atau `scan_orchestrator.py`.

## Struktur Projek

```
oxysintx/
├── app.py             # routing sahaja (backend kekal berasingan/modular)
├── config.py          # paths, secrets, .env
├── requirements.txt
├── auth/              # user_store.py - username/password + role (SQLite)
├── core/              # logging, system monitor, history (SQLite)
├── modules/           # setiap fail = satu recon tool (plugin-style)
├── ai_chat/           # wrapper Anthropic API
└── templates/         # login.html, dashboard.html - SELF-CONTAINED
                        # (CSS + JS projek ini di-inline terus, tiada
                        #  static/css atau static/js berasingan)
```

## Nota Keselamatan

- Password disimpan sebagai hash (bukan plaintext) menggunakan Werkzeug
- Setiap endpoint API disemak role di server (bukan sekadar sorok butang
  di frontend) — Viewer yang cuba panggil endpoint tulis terus dapat 403
- Endpoint `/api/login` ada rate-limit (5 percubaan gagal → lockout 5 minit)
- Jalankan di belakang HTTPS/reverse proxy jika didedahkan ke internet
  (papan tanda "Not secure" di browser bermaksud anda belum buat ini)
- Gunakan hanya pada domain yang anda miliki atau ada kebenaran bertulis
  untuk diuji — ini adalah tanggungjawab anda sepenuhnya

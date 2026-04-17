# 🔐 Laravel File Manager Scanner

**Automated tool for scanning Laravel File Manager**

---

## 🧠 Overview

Tool ini digunakan untuk mendeteksi keberadaan dan konfigurasi Laravel File Manager (LFM) pada target website.

Scanner ini dirancang untuk mengidentifikasi:
Instance LFM yang terbuka tanpa autentikasi
Instance LFM yang memerlukan login (auth-protected)
Endpoint API LFM yang masih aktif

Dengan pendekatan validasi yang lebih ketat, tool ini meminimalisir false positive dan hanya menampilkan hasil yang benar-benar valid.

> ⚠️ Tool ini dibuat hanya untuk **educational purposes** dan **authorized security testing**

---

## 🔍 Detection Logic

1. Protocol Handling
Tool akan mencoba akses menggunakan:
- https://
- http://
- Jika target sudah memiliki skema, maka akan digunakan langsung.

2. Path Enumeration

Scanner akan mengecek beberapa path umum LFM:
- /laravel-filemanager
- /filemanager
- /file-manager

3. Auth Detection (Protected LFM)

Jika response:
- Status: 301 / 302
Redirect ke halaman login
Maka dianggap VULN (Auth)

4. Open LFM Detection (Strict Validation)

Jika response:
- Status: 200
Maka akan dilakukan validasi konten dengan signature khusus:
- id="working_dir"
- id="nav-buttons"
- loadItems()
- refreshContents()
- vendor/laravel-filemanager
Minimal harus ada 2 signature untuk dianggap valid. "OPEN (CONFIRMED)"

5. API-Based Detection

Jika halaman utama tidak valid, tool akan mencoba:
- /initialize
Jika ditemukan response valid seperti:
"disks"
Maka dianggap OPEN (API Valid)

---

## ⚙️ Features
- 🔍 Multi-threaded scanning
- ⚡ Smart protocol fallback (HTTP/HTTPS)
- 🔐 API fallback detection
- 🧪 Strict validation (minimize false positives)
- 🚀 Auto logging hasil scan

## 🛠️ Requirements

- Python 3.x
- requests
- urllib3
- colorama

Install dependencies:
```bash
pip install -r requirements.txt
```
---
USAGE
---
📌 Basic Command with list
```bash
$ python scan.py -l list.txt
```
⚡ Advanced Usage with thread
```bash
$ python scan.py -l targets.txt -t 10
```
---


\# CyberFusion



CyberFusion merupakan aplikasi Cyber Threat Intelligence (CTI) yang mengintegrasikan MISP, VirusTotal, OpenAI, dan Supabase untuk membantu proses analisis ancaman siber secara terpusat.



\---



\# Prasyarat



Sebelum menjalankan aplikasi, pastikan perangkat telah terinstal perangkat lunak berikut:



\## 1. Node.js



Unduh dan instal Node.js versi LTS melalui:



https://nodejs.org



Verifikasi instalasi:



```bash

node -v

npm -v

```



\## 2. Docker Desktop



Unduh dan instal Docker Desktop melalui:



https://www.docker.com/products/docker-desktop/



Verifikasi instalasi:



```bash

docker -v

docker compose version

```



Pastikan Docker Desktop dalam keadaan aktif sebelum melanjutkan proses instalasi.



\---



\# Langkah 1 - Instalasi Dependensi Website



Buka direktori utama CyberFusion kemudian jalankan:



```bash

setup.bat

```


Double-click pada nama file. Tunggu hingga proses instalasi selesai tanpa error.



\---



\# Langkah 2 - Menjalankan MISP Menggunakan Docker



CyberFusion menggunakan MISP sebagai platform Cyber Threat Intelligence. Pada penelitian ini, MISP dijalankan menggunakan Docker image `nukib/misp` yang terhubung dengan MariaDB dan Redis.



Buat folder baru untuk MISP:



```bash

mkdir misp

cd misp

```



Buat file `docker-compose.yml` dengan isi berikut:



```yaml

version: "3.8"



services:

&#x20; redis:

&#x20;   image: redis:7-alpine

&#x20;   restart: unless-stopped



&#x20; db:

&#x20;   image: mariadb:10.11

&#x20;   restart: unless-stopped

&#x20;   environment:

&#x20;     MYSQL\_ROOT\_PASSWORD: rootpassword

&#x20;     MYSQL\_DATABASE: misp

&#x20;     MYSQL\_USER: misp

&#x20;     MYSQL\_PASSWORD: misppassword



&#x20; misp:

&#x20;   image: nukib/misp:latest

&#x20;   restart: unless-stopped

&#x20;   depends\_on:

&#x20;     - db

&#x20;     - redis

&#x20;   ports:

&#x20;     - "80:80"

&#x20;     - "443:443"



volumes:

&#x20; db\_data:

```



Jalankan seluruh container:



```bash

docker compose up -d

```



Periksa status container:



```bash

docker ps

```



Pastikan container berikut berjalan:



\* misp

\* db

\* redis



Tunggu beberapa menit hingga proses inisialisasi selesai.



\---



\# Langkah 3 - Mengakses MISP



Setelah seluruh container berhasil berjalan, buka browser dan akses:



```text

https://localhost

```



atau



```text

http://localhost

```



sesuai konfigurasi yang digunakan.



Masuk menggunakan akun administrator yang telah dikonfigurasi pada MISP.



\---



\# Langkah 4 - Mendapatkan API Key MISP



Setelah berhasil login ke MISP:



1\. Buka menu \*\*Administration\*\*.

2\. Pilih \*\*List Users\*\*.

3\. Pilih akun administrator yang digunakan.

4\. Salin nilai \*\*Auth Key\*\*.



API Key tersebut akan digunakan pada konfigurasi backend CyberFusion.



\---



\# Langkah 5 - Konfigurasi Environment Variable



Pastikan file `.env` backend telah dikonfigurasi dengan benar.



Contoh konfigurasi:



```env

MISP\_URL=https://localhost

MISP\_API\_KEY=YOUR\_MISP\_API\_KEY



VIRUSTOTAL\_API\_KEY=YOUR\_VIRUSTOTAL\_API\_KEY



OPENAI\_API\_KEY=YOUR\_OPENAI\_API\_KEY



SUPABASE\_URL=YOUR\_SUPABASE\_URL

SUPABASE\_ANON\_KEY=YOUR\_SUPABASE\_ANON\_KEY

SUPABASE\_SERVICE\_ROLE\_KEY=YOUR\_SUPABASE\_SERVICE\_ROLE\_KEY

```



Sesuaikan seluruh nilai dengan konfigurasi yang digunakan selama pengembangan.



\---



\# Langkah 6 - Menjalankan Backend



Buka terminal baru.



Masuk ke direktori backend:



```bash

cd Backend-Virustotal-main
```



Jalankan backend:



```bash

npm run dev

```



Tunggu hingga backend berhasil berjalan tanpa error.



\---



\# Langkah 7 - Menjalankan Frontend



Buka terminal baru.



Masuk ke direktori frontend:



```bash

cd UI_UX-CTI-APP-main/UI_UX-CTI-APP-main

```



Jalankan frontend:



```bash

npm run dev

```



Tunggu hingga frontend berhasil berjalan.



\---



\# Langkah 8 - Mengakses Aplikasi



Setelah backend dan frontend berjalan, aplikasi dapat diakses melalui browser.



Frontend:



```text

http://localhost:5173

```



Backend:



```text

http://localhost:3000

```



Port dapat berbeda tergantung konfigurasi yang digunakan.



\---



\# Struktur Direktori



```text

CyberFusion/

│

├── setup.bat

├── README.md

│

├── Backend-Virustotal-main/

│   └── Backend-Virustotal-main/

│       └── Backend-Virustotal-main/

│

└── UI\_UX-CTI-APP-main/

&#x20;   └── UI\_UX-CTI-APP-main/

```



\---



\# Troubleshooting



\## Dependensi Gagal Terinstal



Jalankan kembali:



```bash

setup.bat

```



Pastikan perangkat terhubung ke internet dan Node.js telah terinstal dengan benar.



\---



\## Docker Tidak Berjalan



Pastikan Docker Desktop telah dijalankan sebelum mengeksekusi:



```bash

docker compose up -d

```



\---



\## MISP Tidak Dapat Diakses



Periksa status container:



```bash

docker ps

```



Apabila terdapat container yang berhenti, jalankan kembali:



```bash

docker compose up -d

```



\---



\## Backend Tidak Terhubung ke MISP



Pastikan:



\* MISP telah berjalan dengan normal.

\* URL MISP pada file `.env` sudah sesuai.

\* API Key MISP telah dikonfigurasi dengan benar.

\* Tidak terdapat firewall yang memblokir koneksi.



\---



\# Catatan



CyberFusion memerlukan layanan MISP yang aktif untuk menjalankan proses analisis ancaman siber. Oleh karena itu, pastikan seluruh container MISP telah berjalan dengan baik sebelum menjalankan backend dan frontend.




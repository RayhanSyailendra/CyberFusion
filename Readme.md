\# Panduan Instalasi CyberFusion



\## Prasyarat



Sebelum menjalankan aplikasi, pastikan perangkat telah terpasang perangkat lunak berikut:



\### 1. Node.js



Unduh dan instal Node.js versi LTS.



Setelah instalasi selesai, pastikan Node.js dan npm telah terpasang dengan menjalankan:



```bash

node -v

npm -v

```



\### 2. Docker Desktop



Unduh dan instal Docker Desktop.



Setelah instalasi selesai, pastikan Docker dapat dijalankan dengan perintah:



```bash

docker -v

docker compose version

```



\---



\## Langkah 1 – Instalasi Dependensi Website



Buka direktori utama proyek CyberFusion, kemudian jalankan:



```bash

setup.bat

```



Script tersebut akan menginstal seluruh dependensi frontend dan backend yang dibutuhkan oleh aplikasi.



Tunggu hingga proses instalasi selesai dan tidak terdapat pesan error.



\---



\## Langkah 2 – Menjalankan MISP Menggunakan Docker



install image 'nukib' untuk MISP



Masuk ke direktori MISP Docker:



```bash

cd misp-docker

```



Jalankan seluruh container MISP:



```bash

docker compose up -d

```



Pastikan seluruh container berjalan dengan baik:



```bash

docker ps

```



Tunggu hingga proses inisialisasi MISP selesai sebelum melanjutkan ke langkah berikutnya.



\---



\## Langkah 3 – Konfigurasi Environment Variable



Buat atau sesuaikan file `.env` sesuai kebutuhan aplikasi.



Isi variabel yang diperlukan, seperti:



\* URL MISP

\* API Key MISP

\* API Key VirusTotal

\* API Key OpenAI

\* URL Supabase

\* Anon Key Supabase

\* Service Role Key Supabase



Contoh konfigurasi:



```env

MISP\_URL=http://localhost

MISP\_API\_KEY=YOUR\_API\_KEY

VIRUSTOTAL\_API\_KEY=YOUR\_API\_KEY

OPENAI\_API\_KEY=YOUR\_API\_KEY

```



\---



\## Langkah 4 – Menjalankan Backend



Buka terminal baru dan masuk ke direktori backend:



```bash

cd Backend-Virustotal-main/Backend-Virustotal-main/Backend-Virustotal-main

```



Jalankan backend:



```bash

npm run dev

```



\---



\## Langkah 5 – Menjalankan Frontend



Buka terminal baru dan masuk ke direktori frontend:



```bash

cd UI\_UX-CTI-APP-main/UI\_UX-CTI-APP-main

```



Jalankan frontend:



```bash

npm run dev

```



\---



\## Mengakses Aplikasi



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



\## Troubleshooting



\### Dependensi Gagal Terinstal



Jalankan kembali:



```bash

setup.bat

```



untuk menginstal ulang seluruh dependensi Node.js.



\### Container Docker Tidak Berjalan



Periksa status container:



```bash

docker ps

```



Kemudian jalankan kembali:



```bash

docker compose up -d

```



\### MISP Tidak Dapat Diakses



Pastikan:



\* Docker Desktop sedang berjalan.

\* Seluruh container MISP berstatus aktif.

\* Port yang digunakan MISP tidak digunakan oleh aplikasi lain.



\---



\## Struktur Proyek



```text

CyberFusion/

│

├── setup.bat

├── README.md

├── misp-docker/

├── Backend-Virustotal-main/

└── UI\_UX-CTI-APP-main/

```



\## Catatan



Aplikasi CyberFusion memerlukan layanan MISP yang aktif untuk menjalankan fitur analisis ancaman siber. Oleh karena itu, pastikan seluruh container MISP telah berjalan dengan baik sebelum menjalankan backend dan frontend.




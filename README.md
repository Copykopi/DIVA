# D.I.V.A - Dorking Intelligence & Vulnerability Arsenal

<pre>
=================================================
   Dorking Intelligence & Vulnerability Arsenal
                   (D.I.V.A) 
            | KILLING IN THE NAME |
              - Tool by Copykopi -
=================================================
</pre>

## 📜 Deskripsi

**D.I.V.A** adalah tool otomatisasi berbasis Python yang dirancang untuk mempercepat proses *dorking* dan *initial vulnerability scanning*.

Tool ini menggunakan mesin pencari (DuckDuckGo) untuk menemukan URL yang berpotensi rentan berdasarkan kueri dork yang diberikan pengguna. Setelah itu, D.I.V.A akan memindai URL yang telah difilter untuk mencari kerentanan web umum seperti **SQL Injection (SQLi)** dan **Cross-Site Scripting (XSS)**.

## ✨ Fitur Utama

* **Dorking Cerdas**: Menggunakan `ddgs` untuk mengumpulkan URL target dari kueri dork.
* **Filter Efektif**: Secara otomatis menyaring domain yang tidak relevan (misalnya, `youtube.com`, `github.com`) dan ekstensi file (misalnya, `.pdf`, `.jpg`) untuk fokus pada target yang valid.
* **Pemindaian Multi-Vektor**:
    * **SQLi**: Menguji tiga jenis SQLi (Error-based, Boolean-based, Time-based).
    * **XSS**: Menguji payload XSS dasar untuk mencari refleksi pada parameter.
* **Multithreading**: Melakukan pemindaian URL secara bersamaan (concurrent) menggunakan `ThreadPoolExecutor` untuk kecepatan maksimum.
* **Generator Perintah Lanjutan**: Secara otomatis membuat daftar perintah yang siap di-copy-paste untuk analisis lebih dalam menggunakan tool populer seperti **sqlmap**, **dalfox**, dan **nuclei**.
* **Simpan Laporan**: Menyimpan semua URL yang ditemukan, hasil pemindaian, dan perintah lanjutan ke dalam file output.

## ⚠️ Disclaimer

Tool ini dibuat hanya untuk **tujuan pendidikan** dan **pengujian keamanan yang sah** (misalnya, program bug bounty yang Anda ikuti). Penulis (`Copykopi`) tidak bertanggung jawab atas penyalahgunaan atau aktivitas ilegal apa pun yang dilakukan menggunakan tool ini.

**Gunakan dengan risiko Anda sendiri dan selalu bertindak secara bertanggung jawab.**

## 🚀 Instalasi

1.  Pastikan kamu memiliki **Python 3** terinstal.
2.  bash : git clone https://github.com/Copykopi/DIVA.git
3.  Instal library Python yang diperlukan:

    ```bash
    pip3 install requests ddgs tqdm
    ```

## 🛠️ Penggunaan

Jalankan tool dari terminal menggunakan `python3`.

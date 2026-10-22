# Rule provider (ala Clash) untuk NekoBox

Di editor aturan (Route -> tambah aturan), isi kolom **Domain** atau **IP** dengan baris:

    ruleset:https://contoh.com/daftar.srs

Format yang didukung (dideteksi dari ISI berkas, bukan dari ekstensi URL):
- `.srs`  : rule-set biner sing-box
- `.json` : rule-set sumber sing-box (harus berisi "rules")
- teks / YAML Clash: `payload:` + `+.domain.com`, `.domain.com`, `domain.com`, CIDR IP,
  atau classical: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR, IP-CIDR6
Tidak didukung: `.mrs` (biner mihomo), PROCESS-NAME, GEOIP, dan tipe aturan Clash lain.

Perilaku:
- Diunduh oleh aplikasi saat koneksi dimulai, disimpan di filesDir/ruleset, dianggap segar 12 jam.
- Jika unduhan gagal dan ada salinan lama, salinan lama dipakai.
- Jika gagal dan tidak ada salinan, aturan itu DILEWATI (muncul peringatan), koneksi tetap jalan.
- Beberapa baris ruleset: dalam satu aturan = OR. Hindari mencampur ruleset dengan domain biasa di
  aturan yang sama (sing-box meng-AND jenis field yang berbeda).
- Teks Clash "domain" polos (example.com) dicocokkan persis, sama seperti Clash; gunakan +.example.com
  untuk domain beserta subdomain.

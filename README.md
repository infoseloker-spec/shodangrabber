# Shodan Grabber (Fast + Safe + Interactive)

Tool CLI untuk scrape Shodan dengan rotasi multi API key, mode interaktif, progress realtime, dan dukungan file `dork.txt`.

## Fitur

- Rotasi multi-key + cooldown exponential backoff saat error/rate-limit.
- Bisa proses banyak dork dari file (`--dork-file`) dengan **2 worker paralel**.
- Menampilkan progress scraping per dork dan per page (status mulai, sukses, gagal, retry).
- **Auto-save langsung** setiap ada hasil page (append ke `combined_results.jsonl` saat proses berjalan).
- Jika ada halaman error saat scrape, halaman tersebut di-skip dulu lalu di-**retry di akhir**.
- Interaktif: bisa input list API key langsung dari tools, pilih page per dork, dan target hasil (ribuan).
- Output final hanya 1 set gabungan (tidak dipecah per dork):
  - `IP.txt`
  - `DOMAIN.txt`
  - `IP_PORT.txt`

  (kompatibel juga dibuat: `IP SAJA.txt`, `DOMAIN SAJA.txt`, `IP_PORT SAJA.txt`, `IP:PORT.txt`)
- Di akhir, tool auto dedupe hasil gabungan dan file text output.

## Menyiapkan file dork

Contoh `dork.txt`:

```txt
apache country:ID
nginx port:443 country:SG
# baris komentar akan diabaikan
```

## Cara pakai

### 1) Mode interaktif (disarankan)

```bash
python3 shodan_grabber.py --interactive
```

### 2) Langsung pakai file dork (non-interaktif, key via flag)

```bash
python3 shodan_grabber.py \
  --dork-file dork.txt \
  --pages 10 \
  --target-thousands 2 \
  --key "$SHODAN_KEY_1" \
  --key "$SHODAN_KEY_2" \
  --output-dir output
```

`--target-thousands 2` artinya target ±2000 hasil per dork.

## Catatan aman

- Gunakan minimal 2 API key agar lebih stabil.
- Jangan terlalu agresif menurunkan `--min-interval`.
- Tetap patuhi ToS Shodan dan gunakan hanya untuk aktivitas legal.

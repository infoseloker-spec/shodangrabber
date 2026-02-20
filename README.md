# Shodan Grabber (Fast + Safe + Interactive)

Tool CLI untuk scrape Shodan dengan rotasi multi API key, mode interaktif, dan dukungan file `dork.txt`.

## Fitur

- Rotasi multi-key + cooldown exponential backoff saat error/rate-limit.
- Bisa proses banyak dork dari file (`--dork-file`) dengan **2 worker paralel**.
- Jika ada halaman error saat scrape, halaman tersebut di-skip dulu dan di-**retry di akhir**.
- Interaktif: bisa tanya langsung berapa page per dork dan berapa ribu hasil target.
- Output per dork:
  - raw `.jsonl`
  - `_ip.txt`
  - `_domain.txt`
  - `_ip_port.txt`
- Output gabungan semua dork juga dibuat otomatis.

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
python3 shodan_grabber.py --interactive \
  --key "$SHODAN_KEY_1" \
  --key "$SHODAN_KEY_2"
```

### 2) Langsung pakai file dork

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

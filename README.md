# Shodan Grabber (Fast + Safe)

Tool CLI sederhana untuk ambil data dari Shodan dengan **rotasi 2 API key** supaya lebih cepat dan lebih aman dari rate-limit/error.

## Fitur

- Rotasi multi-key (`--key` bisa dipakai lebih dari 1x).
- Rate-limit per key (`--min-interval`) agar tidak spam request.
- Auto cooldown + exponential backoff saat 429/5xx/network error.
- Auto nonaktifkan key saat invalid (`401`) atau credit habis (`402`).
- Deduplikasi hasil berdasarkan `ip + port`.
- Output ke `jsonl` atau `csv`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Cara pakai

```bash
python shodan_grabber.py "apache country:ID" \
  --key "$SHODAN_KEY_1" \
  --key "$SHODAN_KEY_2" \
  --pages 10 \
  --per-page 100 \
  --min-interval 1.2 \
  --output output/results.jsonl
```

Contoh output CSV:

```bash
python shodan_grabber.py "nginx port:443 country:SG" \
  --key "$SHODAN_KEY_1" \
  --key "$SHODAN_KEY_2" \
  --output output/results.csv
```

## Tips aman biar tidak kena limit

1. Pakai minimal 2 API key.
2. Jangan turunkan `--min-interval` terlalu agresif (rekomendasi 1.0–2.0 detik per key).
3. Batasi `--pages` sesuai kebutuhan.
4. Kalau query berat, jalankan bertahap per negara/ASN.

## Catatan

- Shodan memakai query credits; jika credit salah satu key habis, tool akan pindah ke key lain otomatis.
- Tetap patuhi ToS Shodan dan gunakan hanya untuk aktivitas legal/authorized.

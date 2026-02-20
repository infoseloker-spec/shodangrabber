#!/usr/bin/env python3
"""Fast and safe Shodan grabber with dual API key rotation."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BASE_URL = "https://api.shodan.io"


@dataclass
class KeyState:
    key: str
    next_available_at: float = 0.0
    exhausted: bool = False
    failures: int = 0
    cooldown_until: float = 0.0


@dataclass
class ApiKeyPool:
    keys: list[KeyState]
    min_interval: float = 1.2
    cooldown_seconds: float = 15.0
    _idx: int = field(default=0, init=False)

    def get_key(self) -> KeyState:
        while True:
            available = [k for k in self.keys if not k.exhausted]
            if not available:
                raise RuntimeError("Semua API key sudah habis/terkunci")

            now = time.time()
            candidate = None
            for _ in range(len(self.keys)):
                key_state = self.keys[self._idx % len(self.keys)]
                self._idx += 1
                if key_state.exhausted:
                    continue
                wait_until = max(key_state.next_available_at, key_state.cooldown_until)
                if wait_until <= now:
                    candidate = key_state
                    break

            if candidate:
                candidate.next_available_at = now + self.min_interval
                return candidate

            earliest = min(max(k.next_available_at, k.cooldown_until) for k in available)
            sleep_for = max(0.05, earliest - now)
            time.sleep(sleep_for)

    def mark_rate_limited(self, key_state: KeyState) -> None:
        key_state.failures += 1
        backoff = min(self.cooldown_seconds * (2 ** (key_state.failures - 1)), 180)
        key_state.cooldown_until = time.time() + backoff

    def mark_success(self, key_state: KeyState) -> None:
        key_state.failures = 0
        key_state.cooldown_until = 0.0


class ShodanGrabber:
    def __init__(self, pool: ApiKeyPool, timeout: float = 20.0) -> None:
        self.pool = pool
        self.timeout = timeout

    def search(self, query: str, max_pages: int, per_page: int) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen = set()

        for page in range(1, max_pages + 1):
            data = self._request("/shodan/host/search", {"query": query, "page": page, "minify": "true"})
            matches = data.get("matches", [])
            if not matches:
                break

            for item in matches[:per_page]:
                ip = item.get("ip_str")
                port = item.get("port")
                sig = (ip, port)
                if sig in seen:
                    continue
                seen.add(sig)
                results.append(
                    {
                        "ip": ip,
                        "port": port,
                        "org": item.get("org"),
                        "asn": item.get("asn"),
                        "country": (item.get("location") or {}).get("country_name"),
                        "hostnames": item.get("hostnames", []),
                        "product": item.get("product"),
                        "timestamp": item.get("timestamp"),
                    }
                )

            if len(matches) < per_page:
                break

        return results

    def _request(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        last_error = "unknown"
        for _ in range(30):
            key_state = self.pool.get_key()
            full_params = dict(params)
            full_params["key"] = key_state.key
            query = urllib.parse.urlencode(full_params)
            url = f"{BASE_URL}{endpoint}?{query}"

            try:
                with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as exc:
                status = exc.code
                body = exc.read().decode("utf-8", errors="replace")
            except urllib.error.URLError as exc:
                last_error = str(exc.reason)
                self.pool.mark_rate_limited(key_state)
                continue

            if status == 200:
                self.pool.mark_success(key_state)
                return json.loads(body)

            message = ""
            try:
                message = json.loads(body).get("error", "")
            except Exception:
                message = body[:200]

            if status == 401:
                key_state.exhausted = True
                last_error = f"API key invalid: {message}"
                continue

            if status == 402:
                key_state.exhausted = True
                last_error = f"Query credit habis untuk salah satu key: {message}"
                continue

            if status in (429, 502, 503, 504):
                last_error = f"Temporary error {status}: {message}"
                self.pool.mark_rate_limited(key_state)
                continue

            last_error = f"HTTP {status}: {message}"
            self.pool.mark_rate_limited(key_state)

        raise RuntimeError(f"Gagal request ke Shodan setelah retry: {last_error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shodan grabber cepat + aman dengan rotasi 2 API key")
    parser.add_argument("query", help="Shodan query, contoh: 'apache country:ID'")
    parser.add_argument("--key", action="append", required=True, help="API key Shodan (pakai 2x --key)")
    parser.add_argument("--pages", type=int, default=5, help="Jumlah page yang diambil")
    parser.add_argument("--per-page", type=int, default=100, help="Maksimum item per page yang disimpan")
    parser.add_argument("--min-interval", type=float, default=1.2, help="Jeda minimum per key (detik)")
    parser.add_argument("--cooldown", type=float, default=15.0, help="Cooldown awal jika rate-limit/error")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout per request")
    parser.add_argument("--output", type=Path, default=Path("results.jsonl"), help="Output file (.jsonl atau .csv)")
    return parser.parse_args()


def write_output(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "port", "org", "asn", "country", "hostnames", "product", "timestamp"])
            writer.writeheader()
            for row in rows:
                copy = dict(row)
                copy["hostnames"] = ";".join(copy.get("hostnames") or [])
                writer.writerow(copy)
    else:
        with path.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    args = parse_args()
    if len(args.key) < 2:
        print("[!] Disarankan minimal 2 API key agar stabil dan cepat.", file=sys.stderr)

    pool = ApiKeyPool(
        keys=[KeyState(k.strip()) for k in args.key if k.strip()],
        min_interval=max(args.min_interval, 0.1),
        cooldown_seconds=max(args.cooldown, 1.0),
    )

    if not pool.keys:
        print("[x] Tidak ada API key valid.", file=sys.stderr)
        return 2

    grabber = ShodanGrabber(pool=pool, timeout=max(args.timeout, 3.0))

    try:
        rows = grabber.search(args.query, max_pages=max(args.pages, 1), per_page=max(args.per_page, 1))
    except RuntimeError as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 1

    write_output(args.output, rows)
    print(f"[+] Selesai. Total data unik: {len(rows)}")
    print(f"[+] Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

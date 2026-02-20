#!/usr/bin/env python3
"""Interactive Shodan grabber with key rotation, realtime progress, and autosave."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

BASE_URL = "https://api.shodan.io"
PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


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
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def get_key(self) -> KeyState:
        while True:
            with self._lock:
                available = [k for k in self.keys if not k.exhausted]
                if not available:
                    raise RuntimeError("Semua API key sudah habis/terkunci")

                now = time.time()
                candidate = None
                for _ in range(len(self.keys)):
                    state = self.keys[self._idx % len(self.keys)]
                    self._idx += 1
                    if state.exhausted:
                        continue
                    wait_until = max(state.next_available_at, state.cooldown_until)
                    if wait_until <= now:
                        candidate = state
                        break

                if candidate:
                    candidate.next_available_at = now + self.min_interval
                    return candidate

                earliest = min(max(k.next_available_at, k.cooldown_until) for k in available)

            time.sleep(max(0.05, earliest - time.time()))

    def mark_rate_limited(self, state: KeyState) -> None:
        with self._lock:
            state.failures += 1
            backoff = min(self.cooldown_seconds * (2 ** (state.failures - 1)), 180)
            state.cooldown_until = time.time() + backoff

    def mark_success(self, state: KeyState) -> None:
        with self._lock:
            state.failures = 0
            state.cooldown_until = 0.0


class ShodanGrabber:
    def __init__(self, pool: ApiKeyPool, timeout: float = 20.0) -> None:
        self.pool = pool
        self.timeout = timeout

    def search_pages(
        self,
        query: str,
        pages: list[int],
        per_page: int,
        target_results: int | None,
        on_page: Callable[[int, list[dict[str, Any]]], None] | None = None,
    ) -> tuple[list[dict[str, Any]], list[int]]:
        rows: list[dict[str, Any]] = []
        failed_pages: list[int] = []

        for page in pages:
            log(f"[>] {query} | page {page} mulai scrape...")
            try:
                data = self._request("/shodan/host/search", {"query": query, "page": page, "minify": "true"})
            except RuntimeError as exc:
                failed_pages.append(page)
                log(f"[!] {query} | page {page} gagal, skip dulu ({exc})")
                continue

            matches = data.get("matches", [])
            page_rows: list[dict[str, Any]] = []
            for item in matches[:per_page]:
                page_rows.append(
                    {
                        "ip": item.get("ip_str"),
                        "port": item.get("port"),
                        "org": item.get("org"),
                        "asn": item.get("asn"),
                        "country": (item.get("location") or {}).get("country_name"),
                        "hostnames": item.get("hostnames", []),
                        "product": item.get("product"),
                        "timestamp": item.get("timestamp"),
                        "query": query,
                        "page": page,
                    }
                )

            rows.extend(page_rows)
            if on_page:
                on_page(page, page_rows)
            log(f"[+] {query} | page {page} selesai, hasil page: {len(page_rows)}")

            if target_results and len(rows) >= target_results:
                break
            if len(matches) < per_page:
                break

        return rows, failed_pages

    def _request(self, endpoint: str, params: dict[str, Any]) -> dict[str, Any]:
        last_error = "unknown"
        for _ in range(20):
            key_state = self.pool.get_key()
            full_params = dict(params)
            full_params["key"] = key_state.key
            url = f"{BASE_URL}{endpoint}?{urllib.parse.urlencode(full_params)}"

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
                last_error = f"Query credit habis: {message}"
                continue
            if status in (429, 500, 502, 503, 504):
                last_error = f"Temporary error {status}: {message}"
                self.pool.mark_rate_limited(key_state)
                continue

            last_error = f"HTTP {status}: {message}"
            self.pool.mark_rate_limited(key_state)

        raise RuntimeError(f"Gagal request ke Shodan setelah retry: {last_error}")


def slugify(text: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower()).strip("_")
    return value[:64] if value else "query"


def append_rows_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def write_output(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["ip", "port", "org", "asn", "country", "hostnames", "product", "timestamp", "query", "page"],
            )
            writer.writeheader()
            for row in rows:
                copy = dict(row)
                copy["hostnames"] = ";".join(copy.get("hostnames") or [])
                writer.writerow(copy)
    else:
        with path.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_final_text_outputs(output_dir: Path, rows: list[dict[str, Any]]) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ips = sorted({row.get("ip") for row in rows if row.get("ip")})
    ip_ports = sorted({f"{row.get('ip')}:{row.get('port')}" for row in rows if row.get("ip") and row.get("port")})

    domains_set = set()
    for row in rows:
        for host in row.get("hostnames") or []:
            clean = (host or "").strip().lower()
            if clean:
                domains_set.add(clean)
    domains = sorted(domains_set)

    # Primary output names (simple)
    ip_file = output_dir / "IP.txt"
    domain_file = output_dir / "DOMAIN.txt"
    ip_port_file = output_dir / "IP_PORT.txt"

    ip_content = "\n".join(ips) + ("\n" if ips else "")
    domain_content = "\n".join(domains) + ("\n" if domains else "")
    ip_port_content = "\n".join(ip_ports) + ("\n" if ip_ports else "")

    ip_file.write_text(ip_content, encoding="utf-8")
    domain_file.write_text(domain_content, encoding="utf-8")
    ip_port_file.write_text(ip_port_content, encoding="utf-8")

    # Compatibility aliases so user can find old naming too.
    (output_dir / "IP SAJA.txt").write_text(ip_content, encoding="utf-8")
    (output_dir / "DOMAIN SAJA.txt").write_text(domain_content, encoding="utf-8")
    (output_dir / "IP_PORT SAJA.txt").write_text(ip_port_content, encoding="utf-8")
    (output_dir / "IP:PORT.txt").write_text(ip_port_content, encoding="utf-8")

    return {"ip": ip_file, "domain": domain_file, "ip_port": ip_port_file}


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped = []
    for row in rows:
        sig = (row.get("ip"), row.get("port"))
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(row)
    return deduped


def dedupe_jsonl_file(path: Path) -> list[dict[str, Any]]:
    rows = dedupe_rows(load_jsonl(path))
    write_output(path, rows)
    return rows


class AutosaveAggregator:
    def __init__(self, raw_file: Path) -> None:
        self.raw_file = raw_file
        self._lock = threading.Lock()
        self._seen: set[tuple[Any, Any]] = set()
        self.total_saved = 0
        self.raw_file.parent.mkdir(parents=True, exist_ok=True)
        self.raw_file.write_text("", encoding="utf-8")

    def append_page(self, query: str, page: int, page_rows: list[dict[str, Any]]) -> int:
        with self._lock:
            fresh = []
            for row in page_rows:
                sig = (row.get("ip"), row.get("port"))
                if sig in self._seen:
                    continue
                self._seen.add(sig)
                fresh.append(row)
            append_rows_jsonl(self.raw_file, fresh)
            self.total_saved += len(fresh)
            log(f"[💾] {query} | page {page} autosave +{len(fresh)} (total tersimpan global: {self.total_saved})")
            return len(fresh)


def load_dorks_from_file(path: Path) -> list[str]:
    dorks = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            dorks.append(text)
    return dorks


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Shodan grabber cepat + aman dengan rotasi API key")
    parser.add_argument("query", nargs="?", help="Shodan query tunggal")
    parser.add_argument("--dork-file", type=Path, help="File berisi list dork (1 baris = 1 dork)")
    parser.add_argument("--interactive", action="store_true", help="Mode interaktif")
    parser.add_argument("--key", action="append", help="API key Shodan (disarankan 2 key, bisa diulang)")
    parser.add_argument("--pages", type=int, help="Jumlah page per dork")
    parser.add_argument("--per-page", type=int, default=100, help="Maksimum item per page")
    parser.add_argument("--target-thousands", type=int, help="Target hasil per dork dalam ribuan")
    parser.add_argument("--min-interval", type=float, default=1.2, help="Jeda minimum per key (detik)")
    parser.add_argument("--cooldown", type=float, default=15.0, help="Cooldown awal jika rate-limit/error")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout per request")
    parser.add_argument("--output-dir", type=Path, default=Path("output"), help="Folder output")
    return parser.parse_args()


def resolve_keys(args: argparse.Namespace) -> list[str]:
    keys = [k.strip() for k in (args.key or []) if k and k.strip()]
    if args.interactive and not keys:
        print("Masukan API key Shodan (kosongkan untuk selesai):")
        while True:
            value = input("- key: ").strip()
            if not value:
                break
            keys.append(value)

    unique_keys: list[str] = []
    seen = set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        unique_keys.append(key)

    if not unique_keys:
        raise RuntimeError("Tidak ada API key. Pakai --key atau mode --interactive untuk input key.")
    return unique_keys


def prompt_if_needed(args: argparse.Namespace) -> tuple[list[str], int, int | None]:
    dorks: list[str] = []
    pages = args.pages
    target_results = args.target_thousands * 1000 if args.target_thousands else None

    interactive = args.interactive or (not args.query and not args.dork_file)
    if args.dork_file:
        dorks.extend(load_dorks_from_file(args.dork_file))
    elif args.query:
        dorks.append(args.query)

    if interactive:
        if not dorks:
            source = input("Gunakan file dork? (y/n): ").strip().lower()
            if source == "y":
                dork_path = Path(input("Masukan path dork.txt: ").strip())
                dorks.extend(load_dorks_from_file(dork_path))
            else:
                dorks.append(input("Masukan query dork: ").strip())

        if pages is None:
            raw_pages = input("Berapa page yang ingin di-scrape per dork? (default 5): ").strip()
            pages = int(raw_pages) if raw_pages else 5
        if target_results is None:
            raw_thousands = input("Berapa ribu hasil yang diinginkan per dork? (kosong=tanpa batas): ").strip()
            if raw_thousands:
                target_results = int(raw_thousands) * 1000

    pages = pages if pages and pages > 0 else 5
    dorks = [d for d in dorks if d]
    if not dorks:
        raise RuntimeError("Tidak ada dork yang valid.")
    return dorks, pages, target_results


def process_one_dork(
    grabber: ShodanGrabber,
    query: str,
    pages: int,
    per_page: int,
    target_results: int | None,
    autosaver: AutosaveAggregator,
) -> tuple[str, int, list[int]]:
    def on_page(page: int, page_rows: list[dict[str, Any]]) -> None:
        autosaver.append_page(query, page, page_rows)

    first_rows, failed_pages = grabber.search_pages(query, list(range(1, pages + 1)), per_page, target_results, on_page=on_page)
    retry_rows: list[dict[str, Any]] = []
    if failed_pages:
        log(f"[~] {query} | retry halaman error di akhir: {failed_pages}")
        retry_rows, failed_pages = grabber.search_pages(query, failed_pages, per_page, target_results, on_page=on_page)

    total_rows = len(dedupe_rows(first_rows + retry_rows))
    return query, total_rows, failed_pages


def main() -> int:
    args = parse_args()
    try:
        resolved_keys = resolve_keys(args)
    except RuntimeError as exc:
        print(f"[x] {exc}", file=sys.stderr)
        return 2

    pool = ApiKeyPool(keys=[KeyState(k) for k in resolved_keys], min_interval=max(args.min_interval, 0.1), cooldown_seconds=max(args.cooldown, 1.0))
    if len(pool.keys) < 2:
        print("[!] Disarankan minimal 2 API key agar lebih stabil.", file=sys.stderr)

    try:
        dorks, pages, target_results = prompt_if_needed(args)
    except Exception as exc:
        print(f"[x] Gagal membaca input interaktif: {exc}", file=sys.stderr)
        return 2

    log(f"[+] Mulai scraping | total dork: {len(dorks)} | worker paralel: 2")
    grabber = ShodanGrabber(pool=pool, timeout=max(args.timeout, 3.0))
    combined_file = args.output_dir / "combined_results.jsonl"
    autosaver = AutosaveAggregator(combined_file)

    failed_by_dork: dict[str, list[int]] = {}

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(process_one_dork, grabber, dork, pages, max(args.per_page, 1), target_results, autosaver) for dork in dorks]

        for future in as_completed(futures):
            query, total_rows, failed_pages = future.result()
            log(f"[✓] Dork selesai: {query} | total unik dork (estimasi): {total_rows}")
            if failed_pages:
                failed_by_dork[query] = failed_pages
                log(f"    - halaman gagal setelah retry akhir: {failed_pages}")

    combined_rows = dedupe_jsonl_file(combined_file)
    text_outputs = write_final_text_outputs(args.output_dir, combined_rows)

    log(f"[+] Semua dork selesai. Total gabungan unik: {len(combined_rows)}")
    log(f"[+] Raw gabungan: {combined_file}")
    log(f"[+] IP saja: {text_outputs['ip']}")
    log(f"[+] DOMAIN saja: {text_outputs['domain']}")
    log(f"[+] IP:PORT saja: {text_outputs['ip_port']}")

    if failed_by_dork:
        log("[!] Ada halaman yang tetap gagal setelah retry:")
        for dork, failed_pages in failed_by_dork.items():
            log(f"    - {dork}: {failed_pages}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

import tempfile
import unittest
from pathlib import Path

from shodan_grabber import append_rows_jsonl, dedupe_jsonl_file, write_final_text_outputs


class OutputSplitTests(unittest.TestCase):
    def test_write_final_text_outputs(self):
        rows = [
            {"ip": "1.1.1.1", "port": 80, "hostnames": ["a.example.com", "A.example.com"]},
            {"ip": "2.2.2.2", "port": 443, "hostnames": ["b.example.com", ""]},
            {"ip": "1.1.1.1", "port": 80, "hostnames": []},
        ]

        with tempfile.TemporaryDirectory() as tmp:
            out = write_final_text_outputs(Path(tmp), rows)

            ip_lines = out["ip"].read_text(encoding="utf-8").strip().splitlines()
            domain_lines = out["domain"].read_text(encoding="utf-8").strip().splitlines()
            ip_port_lines = out["ip_port"].read_text(encoding="utf-8").strip().splitlines()

            self.assertEqual(ip_lines, ["1.1.1.1", "2.2.2.2"])
            self.assertEqual(domain_lines, ["a.example.com", "b.example.com"])
            self.assertEqual(ip_port_lines, ["1.1.1.1:80", "2.2.2.2:443"])
            self.assertTrue(out["ip"].name.endswith("IP.txt"))
            self.assertTrue((Path(tmp) / "DOMAIN.txt").exists())
            self.assertTrue((Path(tmp) / "IP_PORT.txt").exists())
            self.assertTrue((Path(tmp) / "IP SAJA.txt").exists())
            self.assertTrue((Path(tmp) / "DOMAIN SAJA.txt").exists())
            self.assertTrue((Path(tmp) / "IP_PORT SAJA.txt").exists())
            self.assertTrue((Path(tmp) / "IP:PORT.txt").exists())

    def test_dedupe_jsonl_file(self):
        rows = [
            {"query": "a", "ip": "1.1.1.1", "port": 80},
            {"query": "a", "ip": "1.1.1.1", "port": 80},
            {"query": "b", "ip": "1.1.1.1", "port": 80},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "raw.jsonl"
            append_rows_jsonl(p, rows)
            out = dedupe_jsonl_file(p)
            self.assertEqual(len(out), 1)
            self.assertEqual(len(p.read_text(encoding="utf-8").strip().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()

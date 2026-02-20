import tempfile
import unittest
from pathlib import Path

from shodan_grabber import write_separated_outputs


class OutputSplitTests(unittest.TestCase):
    def test_write_separated_outputs(self):
        rows = [
            {"ip": "1.1.1.1", "port": 80, "hostnames": ["a.example.com", "A.example.com"]},
            {"ip": "2.2.2.2", "port": 443, "hostnames": ["b.example.com", ""]},
            {"ip": "1.1.1.1", "port": 80, "hostnames": []},
        ]

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "results.jsonl"
            paths = write_separated_outputs(base, rows)

            ip_lines = paths["ip"].read_text(encoding="utf-8").strip().splitlines()
            domain_lines = paths["domain"].read_text(encoding="utf-8").strip().splitlines()
            ip_port_lines = paths["ip_port"].read_text(encoding="utf-8").strip().splitlines()

            self.assertEqual(ip_lines, ["1.1.1.1", "2.2.2.2"])
            self.assertEqual(domain_lines, ["a.example.com", "b.example.com"])
            self.assertEqual(ip_port_lines, ["1.1.1.1:80", "2.2.2.2:443"])


if __name__ == "__main__":
    unittest.main()

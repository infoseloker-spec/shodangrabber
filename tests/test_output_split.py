import tempfile
import unittest
from pathlib import Path

from shodan_grabber import CategoryAutosaver, build_category_sets


class OutputSplitTests(unittest.TestCase):
    def test_build_category_sets(self):
        rows = [
            {"ip": "1.1.1.1", "port": 80, "hostnames": ["a.example.com", "A.example.com"]},
            {"ip": "2.2.2.2", "port": 443, "hostnames": ["b.example.com", ""]},
        ]
        ips, domains, ip_ports = build_category_sets(rows)
        self.assertEqual(ips, {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(domains, {"a.example.com", "b.example.com"})
        self.assertEqual(ip_ports, {"1.1.1.1:80", "2.2.2.2:443"})

    def test_category_autosaver_realtime_and_finalize(self):
        with tempfile.TemporaryDirectory() as tmp:
            saver = CategoryAutosaver(Path(tmp))
            saver.append_rows(
                "dork-a",
                1,
                [
                    {"ip": "1.1.1.1", "port": 80, "hostnames": ["a.example.com"]},
                    {"ip": "1.1.1.1", "port": 80, "hostnames": ["A.example.com"]},
                ],
            )
            saver.append_rows("dork-b", 1, [{"ip": "2.2.2.2", "port": 443, "hostnames": ["b.example.com"]}])
            saver.finalize_sorted_unique()

            self.assertEqual((Path(tmp) / "ip.txt").read_text(encoding="utf-8").strip().splitlines(), ["1.1.1.1", "2.2.2.2"])
            self.assertEqual((Path(tmp) / "domain.txt").read_text(encoding="utf-8").strip().splitlines(), ["a.example.com", "b.example.com"])
            self.assertEqual((Path(tmp) / "ipport.txt").read_text(encoding="utf-8").strip().splitlines(), ["1.1.1.1:80", "2.2.2.2:443"])


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from argparse import Namespace

from shodan_grabber import dedupe_rows, load_dorks_from_file, resolve_keys, slugify


class DorkFlowTests(unittest.TestCase):
    def test_load_dorks_ignores_comment_and_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "dork.txt"
            p.write_text("\n#comment\napache country:ID\n\nnginx port:443\n", encoding="utf-8")
            self.assertEqual(load_dorks_from_file(p), ["apache country:ID", "nginx port:443"])

    def test_dedupe_rows_by_query_ip_port(self):
        rows = [
            {"query": "a", "ip": "1.1.1.1", "port": 80},
            {"query": "a", "ip": "1.1.1.1", "port": 80},
            {"query": "b", "ip": "1.1.1.1", "port": 80},
        ]
        out = dedupe_rows(rows)
        self.assertEqual(len(out), 1)

    def test_slugify(self):
        self.assertEqual(slugify("nginx port:443 country:SG"), "nginx_port_443_country_sg")

    def test_resolve_keys_deduplicate(self):
        args = Namespace(key=["k1", "k1", "k2"], interactive=False)
        self.assertEqual(resolve_keys(args), ["k1", "k2"])

    def test_resolve_keys_error_when_empty_noninteractive(self):
        args = Namespace(key=None, interactive=False)
        with self.assertRaises(RuntimeError):
            resolve_keys(args)

if __name__ == "__main__":
    unittest.main()

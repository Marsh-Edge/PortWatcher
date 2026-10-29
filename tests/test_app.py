"""Tests for the CLI parser and exporters."""

import os
import sys
import csv
import json
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "Protocols"))
sys.path.insert(0, ROOT)

import app  # noqa: E402
from utils import (  # noqa: E402
    export_to_csv, export_to_json, sanitize_filename,
)


class TestPortSpec(unittest.TestCase):
    def test_list(self):
        self.assertEqual(app.parse_port_spec("22,80,443"), [22, 80, 443])

    def test_range_and_list(self):
        self.assertEqual(app.parse_port_spec("80,90-92"), [80, 90, 91, 92])

    def test_duplicates_removed(self):
        self.assertEqual(app.parse_port_spec("80,80,80"), [80])

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            app.parse_port_spec("90-80")

    def test_out_of_range(self):
        with self.assertRaises(ValueError):
            app.parse_port_spec("70000")

    def test_empty(self):
        with self.assertRaises(ValueError):
            app.parse_port_spec(" , ")


class TestParser(unittest.TestCase):
    def test_defaults(self):
        args = app.build_parser().parse_args(["127.0.0.1"])
        self.assertEqual(args.protocol, "tcp")
        self.assertTrue(args.identify)
        self.assertEqual(args.retries, 0)
        self.assertFalse(args.show_filtered)

    def test_disable_identification(self):
        args = app.build_parser().parse_args(["127.0.0.1", "--no-identify"])
        self.assertFalse(args.identify)


class TestExport(unittest.TestCase):
    results = [
        {
            "port": 80,
            "status": "OPEN",
            "service": "HTTP",
            "product": "nginx/1.24",
            "confidence": "high",
        },
        {
            "port": 53,
            "status": "OPEN",
            "service": "DNS",
            "proto": "UDP",
            "confidence": "medium",
        },
    ]

    def test_csv_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "scan.csv")
            self.assertTrue(export_to_csv(self.results, path))
            with open(path, newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["product"], "nginx/1.24")
            self.assertEqual(rows[1]["proto"], "UDP")

    def test_json_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "scan.json")
            self.assertTrue(export_to_json(self.results, path))
            with open(path, encoding="utf-8") as handle:
                rows = json.load(handle)
            self.assertEqual(rows[0]["service"], "HTTP")
            self.assertEqual(rows[0]["confidence"], "high")

    def test_empty_results(self):
        self.assertFalse(export_to_csv([], "unused.csv"))

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("scan?.csv"), "scan_.csv")
        self.assertEqual(sanitize_filename("reports/scan.json"),
                         os.path.join("reports", "scan.json"))


if __name__ == "__main__":
    unittest.main()

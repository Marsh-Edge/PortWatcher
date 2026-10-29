"""Tests for service identification helpers."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "Protocols"))

import services  # noqa: E402


class TestServiceLookup(unittest.TestCase):
    def test_normalize_aliases(self):
        self.assertEqual(services.normalize_service_name("domain"), "DNS")
        self.assertEqual(services.normalize_service_name("microsoft-ds"), "SMB")
        self.assertEqual(services.normalize_service_name("ms-wbt-server"), "RDP")
        self.assertIsNone(services.normalize_service_name(None))

    def test_curated_lookup(self):
        name, confidence = services.lookup_service(3306, "tcp")
        self.assertEqual(name, "MySQL")
        self.assertIn(confidence, ("medium", "low"))

    def test_udp_lookup(self):
        name, _ = services.lookup_service(161, "udp")
        self.assertEqual(name, "SNMP")

    def test_unknown_is_labeled(self):
        name, confidence = services.lookup_service(64999, "tcp")
        self.assertIsInstance(name, str)
        self.assertIn(confidence, ("medium", "low"))


class TestBannerFingerprint(unittest.TestCase):
    def test_http(self):
        data = (b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
                b"X-Powered-By: PHP/8.2\r\n\r\n")
        fingerprint = services.fingerprint_banner(data, 80)
        self.assertEqual(fingerprint["service"], "HTTP")
        self.assertIn("nginx", fingerprint["product"])
        self.assertIn("PHP", fingerprint["product"])

    def test_ssh(self):
        fingerprint = services.fingerprint_banner(
            b"SSH-2.0-OpenSSH_9.6\r\n", 22)
        self.assertEqual(fingerprint["service"], "SSH")
        self.assertEqual(fingerprint["product"], "OpenSSH_9.6")

    def test_mysql_handshake(self):
        version = b"8.0.36-0ubuntu0.22.04.1"
        payload = b"\x0a" + version + b"\x00" + b"\x00" * 16
        packet = bytes([len(payload), 0, 0]) + b"\x00" + payload
        fingerprint = services.fingerprint_banner(packet, 3306)
        self.assertEqual(fingerprint["service"], "MySQL")
        self.assertIn("8.0.36", fingerprint["product"])

    def test_pop3(self):
        fingerprint = services.fingerprint_banner(b"+OK Dovecot ready.\r\n", 110)
        self.assertEqual(fingerprint["service"], "POP3")

    def test_redis(self):
        fingerprint = services.fingerprint_banner(b"+PONG\r\n", 6379)
        self.assertEqual(fingerprint["service"], "Redis")

    def test_udp_dns(self):
        data = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        fingerprint = services.fingerprint_udp_response(data, 53)
        self.assertEqual(fingerprint["service"], "DNS")


class TestLocalHelpers(unittest.TestCase):
    def test_loopback_is_local(self):
        self.assertTrue(services.is_local_target("127.0.0.1"))
        self.assertTrue(services.is_local_target("127.0.0.5"))
        self.assertFalse(services.is_local_target("203.0.113.10"))

    def test_port_owners_shape(self):
        owners = services.local_port_owners()
        self.assertIsInstance(owners, dict)
        for key, value in owners.items():
            self.assertIsInstance(key, tuple)
            self.assertEqual(len(key), 2)
            self.assertIn("pid", value)
            self.assertIn("process", value)
            break


if __name__ == "__main__":
    unittest.main()

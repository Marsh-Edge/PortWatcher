"""Integration tests for the scanners using only loopback sockets."""

import os
import sys
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "Protocols"))

import services  # noqa: E402
import utils  # noqa: E402


class QuietHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD

    def version_string(self):
        return "PortWatcherTest/1.0"

    def log_message(self, *args):
        pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class TestTcpScanner(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_open_port_is_identified_from_banner(self):
        result = utils.scan_tcp_port(
            "127.0.0.1", self.port, timeout=1.0, identify=True,
            banner_timeout=1.0,
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "OPEN")
        self.assertEqual(result["service"], "HTTP")
        self.assertIn("PortWatcherTest", result["product"])
        self.assertEqual(result["confidence"], "high")

    def test_closed_port_is_not_reported(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
        probe.close()
        result = utils.scan_tcp_port("127.0.0.1", free_port, timeout=0.5)
        self.assertIsNone(result)

    def test_local_process_attribution(self):
        result = utils.scan_tcp_port(
            "127.0.0.1", self.port, timeout=1.0, identify=False)
        owners = services.local_port_owners()
        if not owners:
            self.skipTest("process table unavailable on this platform")
        utils.attach_local_processes([result], "127.0.0.1", "127.0.0.1")
        self.assertIn("process", result)
        self.assertTrue(result["process"])


class TestUdpScanner(unittest.TestCase):
    def setUp(self):
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.port_holder = []
        self.thread = threading.Thread(target=self._echo)
        self.thread.daemon = True
        self.thread.start()

    def _echo(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.2)
        self.port_holder.append(sock.getsockname()[1])
        self.ready.set()
        while not self.stop.is_set():
            try:
                data, address = sock.recvfrom(2048)
            except socket.timeout:
                continue
            sock.sendto(data, address)
        sock.close()

    def tearDown(self):
        self.stop.set()
        self.thread.join(timeout=2)

    def test_udp_response_marks_open(self):
        self.assertTrue(self.ready.wait(2.0))
        port = self.port_holder[0]
        result = utils.scan_udp_port(
            "127.0.0.1", port, timeout=1.0, retries=1)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "OPEN")


class TestBoundedRunner(unittest.TestCase):
    def test_collects_every_result(self):
        items = list(range(25))

        def worker(item):
            return {"port": item, "status": "OPEN", "service": "Test"}

        results, interrupted = utils.run_threaded_scan(
            worker, items, max_workers=4, show_progress=False)
        self.assertFalse(interrupted)
        self.assertEqual(len(results), 25)
        self.assertEqual(sorted(row["port"] for row in results), items)

    def test_worker_exception_does_not_abort(self):
        def worker(item):
            if item == 0:
                raise RuntimeError("boom")
            return {"port": item, "status": "OPEN", "service": "Test"}

        results, interrupted = utils.run_threaded_scan(
            worker, list(range(10)), max_workers=2, show_progress=False)
        self.assertFalse(interrupted)
        self.assertEqual(len(results), 9)


if __name__ == "__main__":
    unittest.main()

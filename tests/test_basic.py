import unittest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import PortScanner, ScanResult


class TestPortScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = PortScanner("test.example.com", timeout=0.1, max_threads=5)

    @patch("scanner.socket.socket")
    def test_scan_port_open(self, mock_socket):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        with patch.object(self.scanner, "_resolve_target", return_value="1.2.3.4"):
            result = self.scanner._scan_port(80)
        self.assertEqual(result.port, 80)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.service, "HTTP")

    @patch("scanner.socket.socket")
    def test_scan_port_closed(self, mock_socket):
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1
        with patch.object(self.scanner, "_resolve_target", return_value="1.2.3.4"):
            result = self.scanner._scan_port(81)
        self.assertEqual(result.port, 81)
        self.assertEqual(result.state, "closed")

    def test_guess_service_known(self):
        self.assertEqual(PortScanner._guess_service(22), "SSH")
        self.assertEqual(PortScanner._guess_service(443), "HTTPS")
        self.assertEqual(PortScanner._guess_service(3306), "MySQL")

    def test_guess_service_unknown(self):
        self.assertEqual(PortScanner._guess_service(9999), "unknown")

    def test_resolve_target_invalid(self):
        bad_scanner = PortScanner("nonexistent.invalid")
        with self.assertRaises(ValueError):
            bad_scanner._resolve_target()

    def test_open_ports_filter(self):
        self.scanner.results = [
            ScanResult(port=80, state="open"),
            ScanResult(port=81, state="closed"),
        ]
        self.assertEqual(len(self.scanner.open_ports()), 1)
        self.assertEqual(self.scanner.open_ports()[0].port, 80)

    def test_summary(self):
        self.scanner.results = [ScanResult(port=80, state="open"),
                                 ScanResult(port=81, state="closed")]
        s = self.scanner.summary()
        self.assertEqual(s["target"], "test.example.com")
        self.assertEqual(s["ports_scanned"], 2)
        self.assertEqual(s["open_ports"], 1)


if __name__ == "__main__":
    unittest.main()

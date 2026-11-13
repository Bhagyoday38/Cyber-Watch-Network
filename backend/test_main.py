import asyncio
import unittest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from unittest.mock import patch

from fastapi import HTTPException

from main import (
    analyze_file,
    packet_subscribers,
    classify_packet,
    is_allowed_origin,
    publish_packet,
    scan_attempts,
    validate_upload_content,
)


class PacketClassificationTests(unittest.TestCase):
    def setUp(self):
        scan_attempts.clear()

    def test_classification_score_is_deterministic(self):
        packet = IP() / TCP(dport=445, flags="A")

        self.assertEqual(classify_packet(packet), ("Suspicious", 55, "SMB"))

    def test_one_syn_to_a_common_port_is_not_a_port_scan(self):
        packet = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=80, flags="S")
        packet.time = 100

        self.assertEqual(classify_packet(packet), ("Normal", 5, "None"))

    def test_unique_syn_ports_within_window_are_classified_as_scan(self):
        result = None
        for index, port in enumerate((22, 80, 443, 3306, 5432)):
            packet = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=port, flags="S")
            packet.time = 100 + index
            result = classify_packet(packet)

        self.assertEqual(result, ("Suspicious", 55, "Port Scan"))

    def test_large_dns_queries_are_not_mislabeled_as_amplification(self):
        packet = IP() / UDP(sport=12345, dport=53) / Raw(load=b"x" * 600)

        self.assertEqual(classify_packet(packet), ("Normal", 5, "None"))

    def test_large_dns_responses_are_flagged(self):
        packet = IP() / UDP(sport=53, dport=12345) / Raw(load=b"x" * 600)

        self.assertEqual(classify_packet(packet), ("Suspicious", 60, "Large DNS Response"))

    def test_executable_magic_is_not_reported_as_safe(self):
        result = analyze_file("report.pdf", b"MZ" + b"\x00" * 100)

        self.assertEqual(result["status"], "Malicious")

    def test_unflagged_file_is_not_described_as_proven_safe(self):
        result = analyze_file("report.pdf", b"%PDF sample")

        self.assertEqual(result["status"], "No known indicators")

    def test_packet_is_published_to_every_subscriber(self):
        first = asyncio.Queue()
        second = asyncio.Queue()
        packet_subscribers.update((first, second))
        packet = {"source": "192.0.2.1"}

        try:
            publish_packet(packet)

            self.assertEqual(first.get_nowait(), packet)
            self.assertEqual(second.get_nowait(), packet)
        finally:
            packet_subscribers.difference_update((first, second))

    def test_browser_origins_are_limited_to_local_dashboard(self):
        self.assertTrue(is_allowed_origin("http://localhost:5173"))
        self.assertTrue(is_allowed_origin("http://127.0.0.1:5173"))
        self.assertFalse(is_allowed_origin("https://untrusted.example"))

    def test_slow_subscriber_drops_oldest_packet(self):
        subscriber = asyncio.Queue(maxsize=1)
        packet_subscribers.add(subscriber)

        try:
            publish_packet({"source": "old"})
            publish_packet({"source": "new"})

            self.assertEqual(subscriber.get_nowait(), {"source": "new"})
        finally:
            packet_subscribers.discard(subscriber)


class UploadLimitTests(unittest.TestCase):
    def test_upload_over_limit_is_rejected(self):
        with patch("main.MAX_UPLOAD_SIZE", 4):
            with self.assertRaises(HTTPException) as context:
                validate_upload_content(b"x" * 5)

        self.assertEqual(context.exception.status_code, 413)

    def test_upload_at_limit_is_allowed(self):
        with patch("main.MAX_UPLOAD_SIZE", 4):
            validate_upload_content(b"x" * 4)

    def test_empty_upload_is_rejected(self):
        with self.assertRaises(HTTPException) as context:
            validate_upload_content(b"")

        self.assertEqual(context.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()

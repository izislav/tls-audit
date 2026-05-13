import unittest
from unittest.mock import patch

from tls_guard import scanner
from tls_guard.models import CertificateInfo, CipherProbe, HeaderInfo, ProtocolCheck
from tls_guard.scanner import (
    cipher_name_is_weak,
    evaluate,
    hsts_is_strong,
    parse_hsts,
    parse_target,
)


class ParseTargetTests(unittest.TestCase):
    def test_plain_hostname_defaults_to_443(self) -> None:
        self.assertEqual(parse_target("Example.COM"), ("example.com", 443))

    def test_hostname_with_port(self) -> None:
        self.assertEqual(parse_target("example.com:8443"), ("example.com", 8443))

    def test_rejects_paths(self) -> None:
        with self.assertRaises(ValueError):
            parse_target("https://example.com/admin")


class HstsTests(unittest.TestCase):
    def test_strong_hsts(self) -> None:
        self.assertTrue(hsts_is_strong("max-age=31536000; includeSubDomains"))

    def test_short_hsts(self) -> None:
        self.assertFalse(hsts_is_strong("max-age=60"))

    def test_parse_hsts_flags(self) -> None:
        self.assertEqual(
            parse_hsts("max-age=31536000; includeSubDomains; preload"),
            (31536000, True, True),
        )


class CipherTests(unittest.TestCase):
    def test_detects_weak_cipher_name(self) -> None:
        self.assertTrue(cipher_name_is_weak("DES-CBC3-SHA"))

    def test_allows_aead_cipher_name(self) -> None:
        self.assertFalse(cipher_name_is_weak("TLS_AES_256_GCM_SHA384"))


class GradingTests(unittest.TestCase):
    def test_modern_hsts_site_gets_a_plus(self) -> None:
        cert = CertificateInfo(
            trusted=True,
            subject_alt_names=["example.com"],
            chain_length=2,
        )
        protocols = [
            ProtocolCheck("TLS 1.0", False),
            ProtocolCheck("TLS 1.1", False),
            ProtocolCheck("TLS 1.2", True, "TLS_AES_128_GCM_SHA256"),
            ProtocolCheck("TLS 1.3", True, "TLS_AES_256_GCM_SHA384"),
        ]
        findings, grade, score = evaluate(
            cert,
            protocols,
            [],
            HeaderInfo(
                hsts="max-age=31536000; includeSubDomains",
                hsts_max_age=31536000,
                hsts_include_subdomains=True,
                content_security_policy="default-src 'self'",
                x_content_type_options="nosniff",
            ),
        )
        self.assertEqual([item.code for item in findings], ["hsts_preload_missing"])
        self.assertEqual(findings[0].severity, "info")
        self.assertEqual(grade, "A+")
        self.assertEqual(score, 100)

    def test_untrusted_certificate_gets_d(self) -> None:
        cert = CertificateInfo(trusted=False, validation_error="hostname mismatch")
        protocols = [ProtocolCheck("TLS 1.2", True, "ECDHE-RSA-AES128-GCM-SHA256")]
        findings, grade, score = evaluate(cert, protocols, [], HeaderInfo())
        self.assertEqual(grade, "D")
        self.assertEqual(score, 40)
        self.assertTrue(any(item.code == "certificate_trust" for item in findings))


class ProgressTests(unittest.TestCase):
    def test_scan_host_reports_progress(self) -> None:
        events = []

        def fake_protocol(host, port, name, version, timeout):
            supported = name in {"TLS 1.2", "TLS 1.3"}
            cipher = "TLS_AES_128_GCM_SHA256" if supported else None
            return ProtocolCheck(name, supported, cipher)

        def fake_cipher(host, port, cipher_name, issue, timeout):
            return CipherProbe(cipher_name, "TLS 1.2", False, issue)

        with patch.object(scanner, "resolve_addresses", return_value=["93.184.216.34"]), \
            patch.object(
                scanner,
                "fetch_certificate_info",
                return_value=CertificateInfo(
                    trusted=True,
                    subject_alt_names=["example.com"],
                    chain_length=2,
                ),
            ), \
            patch.object(scanner, "check_protocol", side_effect=fake_protocol), \
            patch.object(scanner, "check_cipher", side_effect=fake_cipher), \
            patch.object(
                scanner,
                "fetch_headers",
                return_value=HeaderInfo(
                    hsts="max-age=31536000; includeSubDomains",
                    hsts_max_age=31536000,
                    hsts_include_subdomains=True,
                    content_security_policy="default-src 'self'",
                    x_content_type_options="nosniff",
                ),
            ):
            result = scanner.scan_host(
                "example.com",
                progress_callback=lambda percent, stage, detail: events.append(
                    (percent, stage, detail)
                ),
            )

        self.assertEqual(result.grade, "A+")
        self.assertEqual(events[0][0], 2)
        self.assertEqual(events[-1], (100, "done", "Проверка завершена"))
        self.assertEqual(
            [percent for percent, _stage, _detail in events],
            sorted(percent for percent, _stage, _detail in events),
        )


if __name__ == "__main__":
    unittest.main()

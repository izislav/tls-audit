import unittest

from shared.tls_audit.report import Report
from shared.tls_audit.testssl import merge_testssl_result


class TestTestsslParser(unittest.TestCase):
    def test_merges_vulnerability_and_cipher_data(self) -> None:
        report = Report(host="example.ru", port=443, score=100, grade="A+")
        result = {
            "enabled": True,
            "exit_code": 0,
            "json": {
                "version": "3.2.1",
                "scanTime": 12,
                "scanResult": [
                    {
                        "ip": "203.0.113.10",
                        "protocols": [
                            {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
                            {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
                        ],
                        "cipherTests": [
                            {
                                "id": "cipher-tls1_2_xc014",
                                "severity": "LOW",
                                "finding": "TLS 1.2 xc014 ECDHE-RSA-AES256-SHA ECDH 253 AES 256",
                            }
                        ],
                        "serverPreferences": [],
                        "serverDefaults": [
                            {"id": "OCSP_stapling", "severity": "OK", "finding": "offered"},
                            {"id": "cert_trust", "severity": "OK", "finding": "Ok via SAN"},
                            {
                                "id": "cert_chain_of_trust",
                                "severity": "OK",
                                "finding": "passed.",
                            },
                        ],
                        "vulnerabilities": [
                            {
                                "id": "BREACH",
                                "severity": "MEDIUM",
                                "cve": "CVE-2013-3587",
                                "finding": "potentially VULNERABLE",
                            },
                            {
                                "id": "POODLE_SSL",
                                "severity": "OK",
                                "finding": "not vulnerable",
                            },
                        ],
                    }
                ],
            },
        }

        merged = merge_testssl_result(report, result)

        self.assertEqual(merged.vulnerabilities["problem_count"], 1)
        self.assertEqual(len(merged.cipher_suites["testssl_cipher_tests"]), 1)
        self.assertEqual(merged.ocsp["status"], "offered")
        self.assertEqual(merged.chain["status"], "checked")
        self.assertTrue(any(item.code == "testssl_breach" for item in merged.findings))
        self.assertFalse(any(item.code == "testssl_poodle_ssl" for item in merged.findings))
        self.assertTrue(
            any(
                item.recommendation.code == "breach_http_compression"
                for item in merged.findings
            )
        )
        breach = next(item for item in merged.findings if item.code == "testssl_breach")
        self.assertIsNone(breach.grade_cap)
        self.assertEqual(merged.score, 90)
        self.assertEqual(merged.grade, "A")

    def test_ocsp_stapling_not_offered_becomes_info_finding(self) -> None:
        report = Report(host="example.ru", port=443)
        result = {
            "enabled": True,
            "json": {
                "scanResult": [
                    {
                        "protocols": [],
                        "cipherTests": [],
                        "serverPreferences": [],
                        "serverDefaults": [
                            {
                                "id": "OCSP_stapling",
                                "severity": "LOW",
                                "finding": "not offered",
                            }
                        ],
                        "vulnerabilities": [],
                    }
                ]
            },
        }

        merged = merge_testssl_result(report, result)

        self.assertEqual(merged.ocsp["status"], "not_offered")
        self.assertTrue(
            any(item.code == "ocsp_stapling_missing" for item in merged.findings)
        )
        ocsp = next(item for item in merged.findings if item.code == "ocsp_stapling_missing")
        self.assertEqual(ocsp.severity, "info")
        self.assertEqual(merged.score, 100)
        self.assertTrue(
            any(
                item.recommendation.code == "enable_ocsp_stapling"
                for item in merged.findings
            )
        )

    def test_lucky13_is_info_when_tls10_and_tls11_are_disabled(self) -> None:
        report = Report(host="example.ru", port=443)
        result = {
            "enabled": True,
            "json": {
                "scanResult": [
                    {
                        "protocols": [
                            {"id": "TLS1", "severity": "INFO", "finding": "not offered"},
                            {
                                "id": "TLS1_1",
                                "severity": "INFO",
                                "finding": "not offered",
                            },
                            {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
                        ],
                        "cipherTests": [],
                        "serverPreferences": [],
                        "serverDefaults": [],
                        "vulnerabilities": [
                            {
                                "id": "LUCKY13",
                                "severity": "LOW",
                                "cve": "CVE-2013-0169",
                                "finding": "potentially vulnerable, uses TLS CBC ciphers",
                            }
                        ],
                    }
                ]
            },
        }

        merged = merge_testssl_result(report, result)
        lucky13 = next(item for item in merged.findings if item.code == "testssl_lucky13")

        self.assertEqual(merged.score, 100)
        self.assertEqual(merged.grade, "A+")
        self.assertEqual(merged.vulnerabilities["problem_count"], 0)
        self.assertEqual(merged.vulnerabilities["items"][0]["severity"], "INFO")
        self.assertEqual(lucky13.severity, "info")
        self.assertEqual(lucky13.title, "Напоминание о CBC suites / Lucky13")
        self.assertIn("Баллы не снимаются", lucky13.detail)
        self.assertTrue(
            any(
                item.recommendation.code == "lucky13_cbc_ciphers"
                for item in merged.findings
            )
        )

    def test_lucky13_still_penalizes_when_legacy_protocol_state_is_unknown(self) -> None:
        report = Report(host="example.ru", port=443)
        result = {
            "enabled": True,
            "json": {
                "scanResult": [
                    {
                        "protocols": [
                            {"id": "TLS1_2", "severity": "OK", "finding": "offered"}
                        ],
                        "cipherTests": [],
                        "serverPreferences": [],
                        "serverDefaults": [],
                        "vulnerabilities": [
                            {
                                "id": "LUCKY13",
                                "severity": "LOW",
                                "finding": "potentially vulnerable, uses TLS CBC ciphers",
                            }
                        ],
                    }
                ]
            },
        }

        merged = merge_testssl_result(report, result)
        lucky13 = next(item for item in merged.findings if item.code == "testssl_lucky13")

        self.assertEqual(merged.score, 95)
        self.assertEqual(merged.vulnerabilities["problem_count"], 1)
        self.assertEqual(lucky13.severity, "low")

    def test_missing_testssl_does_not_break_report(self) -> None:
        report = Report(host="example.ru", port=443)
        merged = merge_testssl_result(report, {"enabled": False, "error": "missing"})

        self.assertEqual(merged.vulnerabilities["testssl_status"], "disabled")
        self.assertEqual(merged.grade, "A+")


if __name__ == "__main__":
    unittest.main()

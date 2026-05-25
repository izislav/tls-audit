import unittest
from unittest.mock import patch

from shared.tls_audit.recommendations import TLS12_13_ONLY
from shared.tls_audit.archive import NullArchiveStore, create_archive_store, job_to_archive_dict
from shared.tls_audit.adapter import build_basic_provenance, convert_findings
from shared.tls_audit.compare import compare_reports, summarize_report
from shared.tls_audit.denylist import Denylist
from shared.tls_audit.jobs import InMemoryJobStore, JobRecord
from shared.tls_audit.report import Finding, Report
from shared.tls_audit.russian_trust import (
    analyze_russian_tls,
    is_stale,
    load_russian_trust_list,
)
from shared.tls_audit.scoring import score_report
from shared.tls_audit.traffic_control import RollingRateLimiter, TargetScanGuard
from shared.tls_audit.validation import (
    is_public_address,
    parse_host,
    resolve_public_addresses,
    validate_target,
    validate_worker_target,
)


class SharedScoringTests(unittest.TestCase):
    def test_grade_cap_is_explained(self) -> None:
        report = Report(host="example.ru")
        report.findings.append(
            Finding(
                severity="high",
                code="legacy_tls",
                category="tls",
                title="Включён устаревший TLS",
                detail="TLS 1.1 supported.",
                recommendation=TLS12_13_ONLY,
                grade_cap="B",
            )
        )

        scored = score_report(report)

        self.assertEqual(scored.grade, "B")
        self.assertTrue(scored.summary[0].startswith("Оценка ограничена до B"))

    def test_repeated_cbc_cipher_class_penalizes_once_and_caps_at_b(self) -> None:
        report = Report(host="example.ru")
        for detail in ["AES128-SHA", "AES256-SHA"]:
            report.findings.append(
                Finding(
                    severity="medium",
                    code="weak_cipher_cbc_accepted",
                    category="cipher",
                    title="Сервер принимает CBC cipher suite",
                    detail=detail,
                    recommendation=TLS12_13_ONLY,
                    grade_cap="B",
                )
            )

        scored = score_report(report)

        self.assertEqual(scored.score, 90)
        self.assertEqual(scored.grade, "B")

    def test_basic_scanner_maps_cipher_caps_by_cipher_class(self) -> None:
        findings = convert_findings(
            [
                {
                    "severity": "medium",
                    "code": "weak_cipher_cbc_accepted",
                    "category": "cipher",
                    "title": "CBC",
                    "detail": "AES128-SHA",
                },
                {
                    "severity": "critical",
                    "code": "weak_cipher_dangerous",
                    "category": "cipher",
                    "title": "NULL",
                    "detail": "NULL-SHA",
                },
            ]
        )

        caps = {item.code: item.grade_cap for item in findings}
        self.assertEqual(caps["weak_cipher_cbc_accepted"], "B")
        self.assertEqual(caps["weak_cipher_dangerous"], "D")

    def test_legacy_f_and_t_caps_are_displayed_as_d(self) -> None:
        report = Report(host="example.ru")
        for cap in ["F", "T"]:
            report.findings.append(
                Finding(
                    severity="critical",
                    code=f"critical_{cap.lower()}",
                    category="tls",
                    title=f"Legacy cap {cap}",
                    detail="Old scanner cap.",
                    recommendation=TLS12_13_ONLY,
                    grade_cap=cap,
                )
            )

        scored = score_report(report)

        self.assertEqual(scored.grade, "D")
        self.assertEqual(scored.score, 40)
        self.assertEqual(scored.raw["scoring"]["raw_score"], 0)
        self.assertTrue(all("до D" in item for item in scored.summary))

    def test_basic_provenance_includes_scanner_versions_and_sources(self) -> None:
        provenance = build_basic_provenance(
            {
                "host": "example.ru",
                "port": 443,
                "scanned_at": "2026-05-25T10:00:00+00:00",
                "addresses": ["93.184.216.34"],
                "headers": {"server": "nginx"},
            }
        )

        self.assertEqual(provenance["report_version"], "0.2")
        self.assertEqual(
            [item["id"] for item in provenance["sources"]],
            ["basic_scanner", "dns_probe", "openssl", "http_headers"],
        )
        self.assertTrue(provenance["sources"][0]["version"])
        self.assertEqual(provenance["sources"][1]["addresses"], ["93.184.216.34"])


class SharedValidationTests(unittest.TestCase):
    def test_parse_host_defaults_to_443(self) -> None:
        self.assertEqual(parse_host("Example.RU"), ("example.ru", 443))

    def test_parse_host_rejects_path(self) -> None:
        with self.assertRaises(ValueError):
            parse_host("https://example.ru/admin")

    def test_private_ip_is_not_public(self) -> None:
        self.assertFalse(is_public_address("127.0.0.1"))
        self.assertFalse(is_public_address("10.0.0.1"))
        self.assertFalse(is_public_address("169.254.169.254"))

    def test_blocked_service_port_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_target("example.ru", 22, resolve=False)

    def test_service_hostname_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_target("localhost", 443, resolve=False)

    def test_dns_rejects_any_private_address(self) -> None:
        with patch(
            "shared.tls_audit.validation.socket.getaddrinfo",
            return_value=[
                (None, None, None, "", ("93.184.216.34", 443)),
                (None, None, None, "", ("127.0.0.1", 443)),
            ],
        ):
            with self.assertRaises(ValueError):
                resolve_public_addresses("example.ru", 443)

    def test_worker_rejects_rebound_dns(self) -> None:
        with patch(
            "shared.tls_audit.validation.socket.getaddrinfo",
            return_value=[
                (None, None, None, "", ("93.184.216.35", 443)),
            ],
        ):
            with self.assertRaises(ValueError):
                validate_worker_target(
                    "example.ru",
                    443,
                    expected_addresses=["93.184.216.34"],
                )

    def test_worker_accepts_matching_public_dns(self) -> None:
        with patch(
            "shared.tls_audit.validation.socket.getaddrinfo",
            return_value=[
                (None, None, None, "", ("93.184.216.34", 443)),
                (None, None, None, "", ("93.184.216.35", 443)),
            ],
        ):
            target = validate_worker_target(
                "example.ru",
                443,
                expected_addresses=["93.184.216.34"],
            )

        self.assertEqual(target.addresses, ["93.184.216.34", "93.184.216.35"])


class SharedRussianTrustTests(unittest.TestCase):
    def test_load_placeholder(self) -> None:
        trust_list = load_russian_trust_list()
        self.assertTrue(trust_list.roots)
        self.assertEqual(trust_list.source, "manual-placeholder")

    def test_stale_invalid_date(self) -> None:
        self.assertTrue(is_stale("bad-date", 30))

    def test_public_webpki_report_has_no_russian_ca(self) -> None:
        report = Report(host="example.ru")
        report.certificate = {
            "issuer": "C=US, O=Example CA, CN=Example WebPKI",
            "signature_algorithm": "sha256WithRSAEncryption",
            "public_key_algorithm": "rsaEncryption",
            "trusted": True,
        }
        report.protocols = {"items": [{"version": "TLS 1.3", "supported": True}]}

        data = analyze_russian_tls(report)

        self.assertEqual(data["status"], "not_detected")
        self.assertFalse(data["is_russian_ca"])
        self.assertFalse(data["is_gost_certificate"])
        self.assertEqual(data["ordinary_tls"]["status"], "likely_ok")

    def test_gost_and_russian_ca_are_detected_independently(self) -> None:
        report = Report(host="example.ru")
        report.certificate = {
            "issuer": "CN=НУЦ Минцифры РФ",
            "signature_algorithm": "1.2.643.7.1.1.3.2",
            "public_key_algorithm": "ГОСТ Р 34.10-2012",
            "trusted": False,
        }
        report.protocols = {"items": [{"version": "TLS 1.2", "supported": True}]}

        data = analyze_russian_tls(report)

        self.assertEqual(data["status"], "gost_and_russian_ca")
        self.assertTrue(data["is_russian_ca"])
        self.assertTrue(data["is_gost_certificate"])
        self.assertIn("1.2.643.7.1.1.3.2", data["gost"]["oids"])


class SharedJobStoreTests(unittest.TestCase):
    def test_in_memory_store_round_trip(self) -> None:
        store = InMemoryJobStore()
        job = store.create("example.ru", 443, ["93.184.216.34"])
        store.update(job.id, status="running", progress_percent=40)

        loaded = store.get(job.id)

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.status, "running")
        self.assertEqual(loaded.progress_percent, 40)
        self.assertEqual(loaded.addresses, ["93.184.216.34"])

    def test_job_record_from_dict_defaults(self) -> None:
        job = JobRecord.from_dict({"id": "1", "host": "example.ru", "port": 443})

        self.assertEqual(job.status, "queued")
        self.assertEqual(job.progress_detail, "Ожидаем worker")


class SharedArchiveTests(unittest.TestCase):
    def test_empty_database_url_uses_null_archive(self) -> None:
        archive = create_archive_store("")

        self.assertIsInstance(archive, NullArchiveStore)
        self.assertFalse(archive.enabled)

    def test_null_archive_stats(self) -> None:
        archive = NullArchiveStore()

        stats = archive.stats(days=3)

        self.assertFalse(stats["enabled"])
        self.assertEqual(stats["days"], 3)
        self.assertEqual(stats["total_scans"], 0)

    def test_null_archive_previous_report_is_empty(self) -> None:
        archive = NullArchiveStore()

        self.assertIsNone(archive.get_previous_report("scan-1"))

    def test_job_to_archive_dict(self) -> None:
        job = JobRecord(id="1", host="example.ru", port=443, addresses=["93.184.216.34"])

        data = job_to_archive_dict(job)

        self.assertEqual(data["host"], "example.ru")
        self.assertEqual(data["addresses"], ["93.184.216.34"])


class SharedCompareTests(unittest.TestCase):
    def test_compare_reports_finds_added_and_resolved_findings(self) -> None:
        previous = summarize_report(
            "old",
            {
                "host": "example.ru",
                "grade": "B",
                "score": 90,
                "findings": [
                    {
                        "severity": "medium",
                        "code": "hsts_missing",
                        "category": "headers",
                        "title": "Нет HSTS",
                    }
                ],
            },
        )
        current = summarize_report(
            "new",
            {
                "host": "example.ru",
                "grade": "A",
                "score": 96,
                "findings": [
                    {
                        "severity": "info",
                        "code": "hsts_preload_missing",
                        "category": "headers",
                        "title": "Нет preload",
                    }
                ],
            },
        )

        diff = compare_reports(current, previous)

        self.assertTrue(diff["has_previous"])
        self.assertTrue(diff["grade_changed"])
        self.assertEqual(diff["score_delta"], 6)
        self.assertEqual(diff["resolved_findings"][0]["code"], "hsts_missing")
        self.assertEqual(diff["added_findings"][0]["code"], "hsts_preload_missing")

    def test_compare_reports_without_previous_is_quiet(self) -> None:
        current = summarize_report("new", {"findings": []})

        diff = compare_reports(current, None)

        self.assertFalse(diff["has_previous"])
        self.assertIsNone(diff["score_delta"])
        self.assertEqual(diff["added_findings"], [])


class TrafficControlTests(unittest.TestCase):
    def test_memory_rate_limiter_blocks_after_limit(self) -> None:
        limiter = RollingRateLimiter(
            limit=2,
            window_seconds=60,
            captcha_after=1,
        )

        self.assertTrue(limiter.check("203.0.113.7").allowed)
        second = limiter.check("203.0.113.7")
        third = limiter.check("203.0.113.7")

        self.assertTrue(second.allowed)
        self.assertTrue(second.captcha_required)
        self.assertFalse(third.allowed)
        self.assertEqual(third.reason, "rate_limit")
        self.assertGreaterEqual(third.retry_after, 1)

    def test_target_guard_blocks_active_and_then_cooldown(self) -> None:
        guard = TargetScanGuard(cooldown_seconds=30, active_ttl_seconds=60)

        first = guard.reserve("example.ru", 443, "job-1")
        active = guard.reserve("example.ru", 443, "job-2")
        guard.release("example.ru", 443, "job-1", cooldown=True)
        cooldown = guard.reserve("example.ru", 443, "job-3")

        self.assertTrue(first.allowed)
        self.assertFalse(active.allowed)
        self.assertEqual(active.reason, "active")
        self.assertEqual(active.job_id, "job-1")
        self.assertFalse(cooldown.allowed)
        self.assertEqual(cooldown.reason, "cooldown")


class DenylistTests(unittest.TestCase):
    def test_blocks_exact_and_cidr_client_ip(self) -> None:
        denylist = Denylist.from_text(
            client_ips="203.0.113.7, 198.51.100.0/24",
            targets="",
        )

        self.assertFalse(denylist.check_client_ip("203.0.113.7").allowed)
        self.assertFalse(denylist.check_client_ip("198.51.100.42").allowed)
        self.assertTrue(denylist.check_client_ip("192.0.2.10").allowed)

    def test_blocks_exact_target_suffix_and_port_specific_rule(self) -> None:
        denylist = Denylist.from_text(
            client_ips="",
            targets="bad.example, *.noisy.example, special.example:8443",
        )

        self.assertFalse(denylist.check_target("bad.example", 443).allowed)
        self.assertFalse(denylist.check_target("www.noisy.example", 443).allowed)
        self.assertFalse(denylist.check_target("special.example", 8443).allowed)
        self.assertTrue(denylist.check_target("special.example", 443).allowed)
        self.assertTrue(denylist.check_target("good.example", 443).allowed)


if __name__ == "__main__":
    unittest.main()

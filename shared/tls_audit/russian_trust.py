import datetime as dt
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .report import Report


DEFAULT_TRUST_FILE = Path("data/russian_trust/roots.sample.json")

GOST_OIDS = {
    "1.2.643.7.1.1.1.1": "ГОСТ Р 34.10-2012, 256-bit public key",
    "1.2.643.7.1.1.1.2": "ГОСТ Р 34.10-2012, 512-bit public key",
    "1.2.643.7.1.1.2.2": "ГОСТ Р 34.11-2012, 256-bit digest",
    "1.2.643.7.1.1.2.3": "ГОСТ Р 34.11-2012, 512-bit digest",
    "1.2.643.7.1.1.3.2": "ГОСТ Р 34.10-2012 + ГОСТ Р 34.11-2012, 256-bit signature",
    "1.2.643.7.1.1.3.3": "ГОСТ Р 34.10-2012 + ГОСТ Р 34.11-2012, 512-bit signature",
    "1.2.643.2.2.19": "ГОСТ Р 34.10-2001 public key",
    "1.2.643.2.2.20": "ГОСТ Р 34.10-94 public key",
    "1.2.643.2.2.3": "ГОСТ Р 34.10-2001 signature",
    "1.2.643.2.2.9": "ГОСТ Р 34.11-94 digest",
}

GOST_KEYWORDS = (
    "gost",
    "id-tc26",
    "gostr3410",
    "gostr3411",
    "gost2012",
    "гост",
    "34.10-2012",
    "34.11-2012",
)


@dataclass
class RussianTrustList:
    updated_at: str
    source: str
    warning: str
    stale: bool
    roots: List[Dict[str, object]]
    intermediates: List[Dict[str, object]]


def load_russian_trust_list(path: Path = DEFAULT_TRUST_FILE) -> RussianTrustList:
    data = json.loads(path.read_text(encoding="utf-8"))
    updated_at = data.get("updated_at") or "1970-01-01"
    stale_after_days = int(data.get("stale_after_days") or 30)
    stale = is_stale(updated_at, stale_after_days)
    return RussianTrustList(
        updated_at=updated_at,
        source=data.get("source") or "unknown",
        warning=data.get("warning") or "",
        stale=stale,
        roots=data.get("roots") or [],
        intermediates=data.get("intermediates") or [],
    )


def is_stale(updated_at: str, stale_after_days: int) -> bool:
    try:
        parsed = dt.datetime.strptime(updated_at, "%Y-%m-%d").date()
    except ValueError:
        return True
    return (dt.date.today() - parsed).days > stale_after_days


def analyze_russian_tls(
    report: Report, trust_file: Path = DEFAULT_TRUST_FILE
) -> Dict[str, Any]:
    try:
        trust_list = load_russian_trust_list(trust_file)
    except Exception as exc:  # noqa: BLE001 - surfaced as report data.
        return {
            "status": "data_error",
            "status_label": "Не удалось загрузить список российских УЦ",
            "note": "Российская TLS/ГОСТ-совместимость не проверена: список доверия недоступен.",
            "is_russian_ca": False,
            "is_gost_certificate": False,
            "gost_tls_evidence": False,
            "ordinary_tls": ordinary_tls_report(report),
            "trust": {
                "source": str(trust_file),
                "updated_at": "",
                "stale": True,
                "warning": str(exc),
            },
            "matches": {"roots": [], "intermediates": []},
            "gost": {
                "certificate_detected": False,
                "chain_detected": False,
                "tls_evidence_detected": False,
                "markers": [],
                "oids": [],
            },
            "summary": [
                "Список российских корневых/промежуточных УЦ не загружен, поэтому блок РФ/ГОСТ неполный."
            ],
            "recommendations": [
                "Подключите актуальный JSON/YAML список российских УЦ и процедуру обновления перед production."
            ],
        }

    certificate_text = collect_text(report.certificate)
    chain_text = collect_text(report.chain)
    tls_text = collect_text(report.protocols) + collect_text(report.cipher_suites)
    all_text = certificate_text + chain_text + tls_text
    searchable = "\n".join(all_text).casefold()
    fingerprints = collect_fingerprints(report)

    root_matches = match_trust_entries(trust_list.roots, searchable, fingerprints)
    intermediate_matches = match_trust_entries(
        trust_list.intermediates, searchable, fingerprints
    )
    certificate_gost = detect_gost(certificate_text)
    chain_gost = detect_gost(chain_text)
    tls_gost = detect_gost(tls_text)
    all_gost_markers = unique_strings(
        certificate_gost["markers"] + chain_gost["markers"] + tls_gost["markers"]
    )
    all_gost_oids = unique_strings(
        certificate_gost["oids"] + chain_gost["oids"] + tls_gost["oids"]
    )

    is_russian_ca = bool(root_matches or intermediate_matches)
    is_gost_certificate = bool(certificate_gost["detected"])
    gost_tls_evidence = bool(tls_gost["detected"])
    ordinary_tls = ordinary_tls_report(report)
    summary = russian_summary(
        is_russian_ca=is_russian_ca,
        is_gost_certificate=is_gost_certificate,
        gost_tls_evidence=gost_tls_evidence,
        ordinary_tls=ordinary_tls,
        trust_list=trust_list,
    )
    status = russian_status(
        is_russian_ca=is_russian_ca,
        is_gost_certificate=is_gost_certificate,
        gost_tls_evidence=gost_tls_evidence,
        stale=trust_list.stale,
    )

    return {
        "status": status,
        "status_label": status_label(status),
        "note": summary[0] if summary else "",
        "is_russian_ca": is_russian_ca,
        "is_gost_certificate": is_gost_certificate,
        "gost_tls_evidence": gost_tls_evidence,
        "ordinary_tls": ordinary_tls,
        "trust": {
            "source": trust_list.source,
            "updated_at": trust_list.updated_at,
            "stale": trust_list.stale,
            "warning": trust_list.warning,
        },
        "matches": {
            "roots": root_matches,
            "intermediates": intermediate_matches,
        },
        "gost": {
            "certificate_detected": is_gost_certificate,
            "chain_detected": bool(chain_gost["detected"]),
            "tls_evidence_detected": gost_tls_evidence,
            "markers": all_gost_markers,
            "oids": all_gost_oids,
        },
        "summary": summary,
        "recommendations": russian_recommendations(
            is_russian_ca=is_russian_ca,
            is_gost_certificate=is_gost_certificate,
            gost_tls_evidence=gost_tls_evidence,
            ordinary_tls=ordinary_tls,
            trust_list=trust_list,
        ),
    }


def collect_text(value: Any) -> List[str]:
    strings: List[str] = []
    append_text(value, strings)
    return strings


def append_text(value: Any, strings: List[str]) -> None:
    if value is None:
        return
    if isinstance(value, dict):
        for item in value.values():
            append_text(item, strings)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            append_text(item, strings)
        return
    text = str(value)
    if text.lstrip().startswith("-----BEGIN CERTIFICATE-----"):
        return
    strings.append(text)


def collect_fingerprints(report: Report) -> List[str]:
    fingerprints = []
    certificate = report.certificate or {}
    fingerprints.append(normalize_fingerprint(certificate.get("fingerprint_sha256")))
    for item in report.chain.get("testssl_items", []) if report.chain else []:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or "").lower()
        if "fingerprintsha256" in item_id:
            fingerprints.append(normalize_fingerprint(item.get("finding")))
    return [item for item in unique_strings(fingerprints) if item]


def normalize_fingerprint(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").casefold())


def match_trust_entries(
    entries: Iterable[Dict[str, object]], searchable: str, fingerprints: List[str]
) -> List[Dict[str, Any]]:
    matches = []
    for entry in entries:
        markers = [str(item) for item in (entry.get("subject_contains") or []) if item]
        entry_fingerprints = [
            normalize_fingerprint(item)
            for item in (entry.get("fingerprints_sha256") or [])
            if item
        ]
        reasons = []
        for marker in markers:
            if marker.casefold() in searchable:
                reasons.append(f"subject_contains: {marker}")
        for fingerprint in entry_fingerprints:
            if fingerprint and fingerprint in fingerprints:
                reasons.append(f"fingerprint_sha256: {fingerprint}")
        if reasons:
            matches.append(
                {
                    "name": entry.get("name") or "unknown",
                    "type": entry.get("type") or "",
                    "matched_by": reasons,
                    "notes": entry.get("notes") or "",
                }
            )
    return matches


def detect_gost(strings: List[str]) -> Dict[str, Any]:
    searchable = "\n".join(strings).casefold()
    oids = [oid for oid in GOST_OIDS if oid in searchable]
    markers = []
    for oid in oids:
        markers.append(f"{oid}: {GOST_OIDS[oid]}")
    for keyword in GOST_KEYWORDS:
        if keyword.casefold() in searchable:
            markers.append(keyword)
    return {
        "detected": bool(markers),
        "markers": unique_strings(markers),
        "oids": unique_strings(oids),
    }


def ordinary_tls_report(report: Report) -> Dict[str, Any]:
    supported = supported_protocol_names(report)
    trusted = bool((report.certificate or {}).get("trusted"))
    if trusted and ("TLS 1.2" in supported or "TLS 1.3" in supported):
        status = "likely_ok"
        note = "Обычная браузерная совместимость выглядит нормальной по базовой проверке."
    elif trusted:
        status = "partial"
        note = "Сертификат доверенный, но современный TLS 1.2/1.3 не подтвержден в базовой проверке."
    else:
        status = "problem"
        note = "Базовая проверка не подтвердила доверие обычных публичных браузеров к сертификату."
    return {
        "status": status,
        "trusted": trusted,
        "modern_tls_detected": "TLS 1.2" in supported or "TLS 1.3" in supported,
        "supported_protocols": supported,
        "note": note,
    }


def supported_protocol_names(report: Report) -> List[str]:
    names = []
    for item in (report.protocols or {}).get("items", []):
        if isinstance(item, dict) and item.get("supported"):
            names.append(str(item.get("version") or ""))
    for item in (report.protocols or {}).get("testssl", []):
        if not isinstance(item, dict):
            continue
        item_id = str(item.get("id") or "")
        finding = str(item.get("finding") or "").lower()
        if "not offered" in finding:
            continue
        if item_id == "TLS1_2":
            names.append("TLS 1.2")
        elif item_id == "TLS1_3":
            names.append("TLS 1.3")
    return unique_strings([name for name in names if name])


def russian_status(
    *,
    is_russian_ca: bool,
    is_gost_certificate: bool,
    gost_tls_evidence: bool,
    stale: bool,
) -> str:
    if is_gost_certificate and is_russian_ca:
        return "gost_and_russian_ca"
    if is_gost_certificate or gost_tls_evidence:
        return "gost_detected"
    if is_russian_ca:
        return "russian_ca_detected"
    if stale:
        return "trust_list_stale"
    return "not_detected"


def status_label(status: str) -> str:
    labels = {
        "gost_and_russian_ca": "Обнаружены признаки ГОСТ и российского УЦ",
        "gost_detected": "Обнаружены признаки ГОСТ",
        "russian_ca_detected": "Обнаружен российский УЦ",
        "trust_list_stale": "Список российских УЦ требует обновления",
        "not_detected": "ГОСТ/российский УЦ не обнаружены",
        "data_error": "Нет данных для проверки РФ/ГОСТ",
    }
    return labels.get(status, status)


def russian_summary(
    *,
    is_russian_ca: bool,
    is_gost_certificate: bool,
    gost_tls_evidence: bool,
    ordinary_tls: Dict[str, Any],
    trust_list: RussianTrustList,
) -> List[str]:
    items = []
    if is_russian_ca:
        items.append(
            "Цепочка сертификата похожа на российскую по локальному списку доверия. Это отдельная совместимость и она не повышает глобальную TLS-оценку."
        )
    else:
        items.append(
            "Российский УЦ в цепочке не обнаружен по текущему локальному списку. Для обычного публичного сайта это не ошибка."
        )
    if is_gost_certificate:
        items.append(
            "В leaf certificate найдены признаки ГОСТ-алгоритмов. Нужно отдельно проверять поддержку в целевой российской клиентской среде."
        )
    elif gost_tls_evidence:
        items.append(
            "В TLS-данных найдены признаки ГОСТ, но leaf certificate не выглядит как ГОСТ-сертификат по базовым полям."
        )
    else:
        items.append(
            "ГОСТ TLS не обнаружен. Для обычного публичного сайта это не ошибка, но в некоторых российских государственных или корпоративных сценариях может быть требованием."
        )
    items.append(str(ordinary_tls.get("note") or ""))
    if trust_list.stale:
        items.append(
            "Локальный список российских УЦ устарел, поэтому совпадения нужно перепроверить после обновления данных."
        )
    elif trust_list.warning:
        items.append(trust_list.warning)
    return [item for item in items if item]


def russian_recommendations(
    *,
    is_russian_ca: bool,
    is_gost_certificate: bool,
    gost_tls_evidence: bool,
    ordinary_tls: Dict[str, Any],
    trust_list: RussianTrustList,
) -> List[str]:
    recommendations = []
    if trust_list.stale or trust_list.warning:
        recommendations.append(
            "Перед production подключить официальный источник российских корневых/промежуточных УЦ и автоматическое обновление списка."
        )
    if not is_russian_ca:
        recommendations.append(
            "Если нужна российская инфраструктурная совместимость, добавьте отдельный профиль проверки с сертификатом от нужного российского УЦ."
        )
    if not is_gost_certificate and not gost_tls_evidence:
        recommendations.append(
            "Не включайте ГОСТ TLS без бизнес-требования: для большинства публичных сайтов достаточно сильного WebPKI-сертификата и TLS 1.2/1.3."
        )
    if is_gost_certificate or gost_tls_evidence:
        recommendations.append(
            "Проверьте сайт вручную в целевой российской среде: Яндекс Браузер для организаций, КриптоПро CSP и нужные российские ОС/браузеры."
        )
    if ordinary_tls.get("status") != "likely_ok":
        recommendations.append(
            "Сначала исправьте обычную WebPKI/TLS-совместимость: публичные браузеры должны доверять сертификату и видеть TLS 1.2/1.3."
        )
    return unique_strings(recommendations)


def unique_strings(items: Iterable[Any]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        text = str(item or "")
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result

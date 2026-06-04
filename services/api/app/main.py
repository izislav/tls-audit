import logging
import secrets
import subprocess
from datetime import datetime, timezone
from typing import Dict, List
from urllib import error as urllib_error
from urllib import request as urllib_request

try:
    from fastapi import FastAPI, Header, HTTPException, Request
    from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - installed in Docker/runtime.
    raise RuntimeError(
        "FastAPI dependencies are not installed. Install requirements/api.txt."
    ) from exc

from shared.tls_audit.validation import validate_target
from shared.tls_audit.compare import compare_reports, summarize_report
from shared.tls_audit.logging import log_event
from shared.tls_audit.monitor_access import (
    build_monitor_token_secret,
    create_monitor_owner_token as build_owner_token,
    email_from_monitor_owner_token as parse_owner_token,
    monitoring_admin_token_valid,
)
from shared.tls_audit.traffic_control import AdmissionDecision

from .archive import archive_store
from .billing import billing_store
from .denylist import denylist
from .frontend import STATIC_PAGES, render_frontend, render_static_page
from .jobs import job_store
from .monitoring import monitoring_store
from .queue import enqueue_scan_job, queue_depth
from .rate_limit import rate_limiter
from .settings import settings
from .subscriptions import subscription_store
from .target_guard import target_scan_guard
from shared.tls_audit.monitoring_store import (
    DEFAULT_SCAN_INTERVAL_SECONDS,
    MIN_SCAN_INTERVAL_SECONDS,
)
from shared.tls_audit.monitoring_scheduler import schedule_domain_scan
from shared.tls_audit.email_sender import send_email
from shared.tls_audit.monitor_export import monitoring_export_to_csv
import os


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("tls_audit.api")


def frontend_stats() -> Dict[str, object]:
    scan_stats = archive_store.stats(days=3650) if archive_store.enabled else {"total_scans": 0}
    monitored_domains = len(monitoring_store.list_domains(limit=1000)) if monitoring_store.enabled else 0
    return {
        "total_scans": scan_stats.get("total_scans", 0),
        "monitored_domains": monitored_domains,
    }


app = FastAPI(
    title="TLS Audit API",
    version="0.1.0",
    description="Русскоязычный API для проверки HTTPS/TLS-конфигурации сайтов.",
)


class CheckRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


class MonitorDomainRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    scan_interval_seconds: int = Field(default=DEFAULT_SCAN_INTERVAL_SECONDS, ge=1)
    enabled: bool = Field(default=True)
    notes: str = Field(default="", max_length=1000)


class MonitorDomainPatchRequest(BaseModel):
    enabled: bool | None = None
    scan_interval_seconds: int | None = Field(default=None, ge=1)
    notes: str | None = Field(default=None, max_length=1000)


class SubscribeRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)
    email: str = Field(..., min_length=5, max_length=254)
    plan: str = Field(default="free", min_length=3, max_length=16)


class ProCheckoutRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)


class ProActivateDemoRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)


class OwnershipChallengeRequest(BaseModel):
    method: str = Field(default="dns_txt", min_length=3, max_length=32)


def monitor_token_secret() -> str:
    return build_monitor_token_secret(
        monitoring_token_secret=settings.monitoring_token_secret,
        database_url=settings.database_url,
        redis_url=settings.redis_url,
        public_base_url=settings.public_base_url,
        contact_email=settings.contact_email,
    )


def create_monitor_owner_token(email: str) -> str:
    return build_owner_token(email, monitor_token_secret())


def email_from_monitor_owner_token(token: str) -> str | None:
    return parse_owner_token(token, monitor_token_secret())


def require_monitor_owner_token(token: str) -> str:
    email = email_from_monitor_owner_token(token)
    if not email:
        raise HTTPException(
            status_code=403,
            detail="Нужна приватная ссылка управления подпиской.",
        )
    return email


def require_subscription_owner(subscription_id: int, token: str):
    normalized = require_monitor_owner_token(token)
    sub = subscription_store.get_by_id(subscription_id)
    if not sub:
        raise HTTPException(status_code=404, detail="Подписка не найдена.")
    if sub.email != normalized:
        raise HTTPException(status_code=403, detail="Недостаточно прав для этой подписки.")
    return sub


def ownership_http_url(host: str) -> str:
    return f"https://{host}/.well-known/tlsaudit-verification.txt"


def verify_http_file(host: str, token: str, timeout: int = 8) -> tuple[bool, str]:
    url = ownership_http_url(host)
    try:
        with urllib_request.urlopen(url, timeout=timeout) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
    except urllib_error.URLError as exc:
        return False, f"Не удалось получить {url}: {exc}"
    return (token in body, f"Проверен {url}")


def parse_dig_txt_output(output: str) -> list[str]:
    values: list[str] = []
    for line in str(output or "").splitlines():
        text = line.strip()
        if not text:
            continue
        text = text.replace('" "', "").replace('"', "")
        if text:
            values.append(text)
    return values


def lookup_txt_records(name: str) -> tuple[list[str], str]:
    dig = subprocess.run(
        ["dig", "+short", "TXT", name],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    values = parse_dig_txt_output(dig.stdout)
    if values:
        return values, "dig"
    return [], "dig"


def verify_dns_txt(host: str, token: str) -> tuple[bool, str]:
    name = f"_tlsaudit-challenge.{host}"
    values, source = lookup_txt_records(name)
    if not values:
        return False, f"TXT запись {name} не найдена ({source})."
    matched = any(token in value for value in values)
    return matched, f"Проверена TXT запись {name} ({source})."


def require_monitoring_admin_token(
    x_monitoring_admin_token: str | None = None,
) -> None:
    if not monitoring_admin_token_valid(
        settings.monitoring_admin_token,
        x_monitoring_admin_token,
    ):
        raise HTTPException(status_code=404, detail="Not Found")


@app.get("/health")
def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "database": "enabled" if archive_store.enabled else "disabled",
    }


@app.get("/", response_class=HTMLResponse)
def frontend() -> str:
    return render_frontend(frontend_stats())


@app.head("/")
def frontend_head() -> Response:
    return Response()


@app.get("/scan", response_class=HTMLResponse)
def scan_frontend() -> str:
    return render_frontend(frontend_stats())


@app.get("/about", response_class=RedirectResponse)
def about_frontend() -> RedirectResponse:
    return RedirectResponse(url="/", status_code=308)


@app.head("/about")
def about_frontend_head() -> RedirectResponse:
    return RedirectResponse(url="/", status_code=308)


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page() -> str:
    return render_static_page("privacy")


@app.get("/terms", response_class=HTMLResponse)
def terms_page() -> str:
    return render_static_page("terms")


@app.get("/cookies", response_class=HTMLResponse)
def cookies_page() -> str:
    return render_static_page("cookies")


@app.get("/security", response_class=HTMLResponse)
def security_page() -> str:
    return render_static_page("security")


@app.get("/ssl-certificate-check", response_class=HTMLResponse)
def ssl_certificate_check_page() -> str:
    return render_static_page("ssl-certificate-check")


@app.get("/tls-versions-check", response_class=HTMLResponse)
def tls_versions_check_page() -> str:
    return render_static_page("tls-versions-check")


@app.get("/hsts-check", response_class=HTMLResponse)
def hsts_check_page() -> str:
    return render_static_page("hsts-check")


@app.get("/nginx-tls-config", response_class=HTMLResponse)
def nginx_tls_config_page() -> str:
    return render_static_page("nginx-tls-config")


@app.get("/apache-tls-config", response_class=HTMLResponse)
def apache_tls_config_page() -> str:
    return render_static_page("apache-tls-config")


@app.get("/a-plus-grade", response_class=HTMLResponse)
def a_plus_grade_page() -> str:
    return render_static_page("a-plus-grade")


@app.get("/caddy-tls-config", response_class=HTMLResponse)
def caddy_tls_config_page() -> str:
    return render_static_page("caddy-tls-config")


@app.get("/haproxy-tls-config", response_class=HTMLResponse)
def haproxy_tls_config_page() -> str:
    return render_static_page("haproxy-tls-config")


@app.get("/methodology", response_class=HTMLResponse)
def methodology_page() -> str:
    return render_static_page("methodology")


@app.get("/tls-audit-vs-ssl-labs", response_class=HTMLResponse)
def tls_audit_vs_ssl_labs_page() -> str:
    return render_static_page("tls-audit-vs-ssl-labs")


@app.get("/methodology-changelog", response_class=HTMLResponse)
def methodology_changelog_page() -> str:
    return render_static_page("methodology-changelog")


@app.get("/sample-reports", response_class=HTMLResponse)
def sample_reports_page() -> str:
    return render_static_page("sample-reports")


@app.get("/support", response_class=HTMLResponse)
def support_page() -> str:
    return render_frontend(frontend_stats())


@app.get("/monitor-status", response_class=HTMLResponse)
def monitor_status_page() -> str:
    return render_static_page("monitor-status")


@app.post("/api/billing/pro/checkout")
def create_pro_checkout(payload: ProCheckoutRequest) -> Dict[str, object]:
    email = payload.email.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=400, detail="Укажите корректный email.")
    checkout_id = f"pro_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    checkout_url = f"{settings.public_base_url}/"
    billing_store.create_checkout(email, checkout_id)
    return {
        "status": "pending_provider",
        "plan": "pro",
        "price_usd_monthly": 10,
        "domain_limit": 10,
        "checkout_id": checkout_id,
        "checkout_url": checkout_url,
        "message": "Платежный провайдер подключается. Используйте контакт для ручной активации Pro.",
    }


@app.post("/api/billing/pro/activate-demo")
def activate_pro_demo(payload: ProActivateDemoRequest) -> Dict[str, object]:
    email = payload.email.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=400, detail="Укажите корректный email.")
    account = billing_store.activate_pro(email)
    return {
        "status": account.status,
        "plan": "pro",
        "email": account.email,
        "domain_limit": account.domain_limit,
    }


@app.get("/api/billing/pro/status")
def get_pro_status(email: str) -> Dict[str, object]:
    normalized = email.strip().lower()
    account = billing_store.get_by_email(normalized)
    if not account:
        return {"email": normalized, "plan": "free", "status": "inactive", "domain_limit": 1}
    return {
        "email": account.email,
        "plan": "pro" if account.plan == "support" else account.plan,
        "status": account.status,
        "domain_limit": account.domain_limit,
        "checkout_id": account.checkout_id,
    }


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt() -> str:
    return "\n".join(
        [
            "User-agent: *",
            "Allow: /",
            "Disallow: /api/",
            "Disallow: /scan",
            "Disallow: /health",
            f"Sitemap: {settings.public_base_url}/sitemap.xml",
            "",
        ]
    )


@app.get("/.well-known/security.txt", response_class=PlainTextResponse)
def security_txt() -> str:
    return security_txt_body()


@app.get("/security.txt", response_class=PlainTextResponse)
def security_txt_root() -> str:
    return security_txt_body()


@app.get("/sitemap.xml")
def sitemap_xml() -> Response:
    today = datetime.now(timezone.utc).date().isoformat()
    urls = [("/", "1.0"), *[(page["path"], "0.3") for page in STATIC_PAGES.values()]]
    url_items = "\n".join(
        f"""  <url>
    <loc>{settings.public_base_url}{path}</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>{priority}</priority>
  </url>"""
        for path, priority in urls
    )
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{url_items}
</urlset>
"""
    return Response(content=body, media_type="application/xml")


def security_txt_body() -> str:
    expires = datetime(2026, 12, 31, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return "\n".join(
        [
            f"Contact: mailto:{settings.contact_email}",
            "Preferred-Languages: ru, en",
            f"Canonical: {settings.public_base_url}/.well-known/security.txt",
            f"Policy: {settings.public_base_url}/security",
            f"Expires: {expires}",
            "",
        ]
    )


@app.get("/{verification_file}", response_class=PlainTextResponse)
def site_verification_file(verification_file: str) -> str:
    if (
        settings.yandex_verification_file
        and verification_file == settings.yandex_verification_file
        and verification_file.startswith("yandex_")
        and verification_file.endswith(".html")
    ):
        content = settings.yandex_verification_content
        if content and not content.startswith("<") and not content.startswith("Verification:"):
            return "Verification: " + content
        return content or "Verification: " + verification_file.removeprefix("yandex_").removesuffix(".html")
    if (
        settings.google_verification_file
        and verification_file == settings.google_verification_file
        and verification_file.startswith("google")
        and verification_file.endswith(".html")
    ):
        content = settings.google_verification_content
        if content and not content.startswith("google-site-verification:"):
            return "google-site-verification: " + content
        return content or "google-site-verification: " + verification_file
    raise HTTPException(status_code=404, detail="Страница не найдена.")


@app.post("/api/check")
def create_check(payload: CheckRequest, request: Request) -> Dict[str, object]:
    client_ip = request_ip(request)
    client_decision = denylist.check_client_ip(client_ip)
    if not client_decision.allowed:
        log_event(
            logger,
            "scan_rejected",
            reason=client_decision.reason,
            client_ip=client_ip,
            rule=client_decision.rule,
        )
        raise HTTPException(
            status_code=403,
            detail="С этого адреса проверки временно запрещены.",
        )

    rate_decision = rate_limiter.check(client_ip)
    if not rate_decision.allowed:
        log_event(
            logger,
            "scan_rejected",
            reason=rate_decision.reason,
            retry_after=rate_decision.retry_after,
            captcha_required=rate_decision.captcha_required,
        )
        raise admission_error(
            429,
            "Слишком много запросов. Попробуйте повторить позже.",
            rate_decision,
        )

    try:
        parsed_target = validate_target(payload.host, payload.port, resolve=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target_deny_decision = denylist.check_target(parsed_target.host, parsed_target.port)
    if not target_deny_decision.allowed:
        log_event(
            logger,
            "scan_rejected",
            reason=target_deny_decision.reason,
            host=parsed_target.host,
            port=parsed_target.port,
            rule=target_deny_decision.rule,
        )
        raise HTTPException(
            status_code=403,
            detail="Проверка этого домена временно запрещена.",
        )

    try:
        target = validate_target(parsed_target.host, parsed_target.port, resolve=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        depth = queue_depth()
    except Exception as exc:  # noqa: BLE001 - API should fail closed when queue is unreachable.
        log_event(logger, "scan_rejected", reason="queue_unavailable", error=str(exc))
        raise HTTPException(
            status_code=503,
            detail="Очередь проверок временно недоступна.",
        ) from exc

    if settings.max_queue_depth > 0 and depth >= settings.max_queue_depth:
        log_event(logger, "scan_rejected", reason="queue_full", queue_depth=depth)
        raise HTTPException(
            status_code=503,
            detail="Очередь проверок переполнена. Попробуйте позже.",
        )

    job = job_store.create(target.host, target.port, target.addresses)
    target_decision = target_scan_guard.reserve(job.host, job.port, job.id)
    if not target_decision.allowed:
        job_store.delete(job.id)
        status_code = 409 if target_decision.reason == "active" else 429
        log_event(
            logger,
            "scan_rejected",
            reason=target_decision.reason,
            host=target.host,
            port=target.port,
            existing_job=target_decision.job_id,
            retry_after=target_decision.retry_after,
        )
        message = (
            "Проверка этого домена уже выполняется."
            if target_decision.reason == "active"
            else "Этот домен недавно проверяли. Повторите чуть позже."
        )
        raise admission_error(status_code, message, target_decision)

    archive_store.create_scan(job)
    try:
        enqueue_scan_job(
            {
                "id": job.id,
                "host": job.host,
                "port": job.port,
                "addresses": job.addresses,
            }
        )
    except Exception as exc:  # noqa: BLE001 - queue errors become API errors.
        target_scan_guard.release(job.host, job.port, job.id, cooldown=False)
        job_store.update(job.id, status="error", error="Очередь проверок недоступна.")
        log_event(logger, "scan_rejected", reason="enqueue_failed", error=str(exc))
        raise HTTPException(
            status_code=503,
            detail="Не удалось поставить проверку в очередь.",
        ) from exc
    log_event(logger, "scan_queued", host=job.host, port=job.port, job_id=job.id)
    return {
        "id": job.id,
        "status": job.status,
        "host": job.host,
        "port": job.port,
        "addresses": target.addresses,
    }


@app.get("/api/check/{job_id}")
def get_check(job_id: str) -> Dict[str, object]:
    job = job_store.get(job_id)
    if not job and archive_store.enabled:
        archived = archive_store.get_scan(job_id)
        if archived:
            return archived
    if not job:
        raise HTTPException(status_code=404, detail="Проверка не найдена.")
    data = job.to_dict()
    data.pop("report", None)
    return data


@app.get("/api/report/{job_id}")
def get_report(job_id: str) -> Dict[str, object]:
    job = job_store.get(job_id)
    if archive_store.enabled:
        archived = archive_store.get_report(job_id)
        if archived:
            return archived
    if not job:
        raise HTTPException(status_code=404, detail="Проверка не найдена.")
    if job.status != "done" or not job.report:
        raise HTTPException(status_code=409, detail="Отчёт ещё не готов.")
    return job.report


@app.get("/api/report/{job_id}/compare")
def compare_report(job_id: str) -> Dict[str, object]:
    report = get_report(job_id)
    scan = archive_store.get_scan(job_id) if archive_store.enabled else None
    previous = archive_store.get_previous_report(job_id) if archive_store.enabled else None

    current_summary = summarize_report(job_id, report, scan)
    previous_summary = None
    if previous:
        previous_scan = previous.get("scan") or {}
        previous_summary = summarize_report(
            str(previous_scan.get("id") or ""),
            previous.get("report") or {},
            previous_scan,
        )

    return {
        "current": current_summary,
        "previous": previous_summary,
        "diff": compare_reports(current_summary, previous_summary),
    }


@app.get("/api/monitor/domains")
def list_monitor_domains(
    limit: int = 100,
    x_monitoring_admin_token: str | None = Header(default=None),
) -> Dict[str, object]:
    require_monitoring_admin_token(x_monitoring_admin_token)
    domains = monitoring_store.list_domains(limit=max(1, min(limit, 500)))
    return {"items": [domain_to_dict(item) for item in domains]}


@app.post("/api/monitor/domains")
def upsert_monitor_domain(
    payload: MonitorDomainRequest,
    x_monitoring_admin_token: str | None = Header(default=None),
) -> Dict[str, object]:
    require_monitoring_admin_token(x_monitoring_admin_token)
    if payload.scan_interval_seconds < MIN_SCAN_INTERVAL_SECONDS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Интервал мониторинга слишком маленький. "
                f"Минимум: {MIN_SCAN_INTERVAL_SECONDS} секунд."
            ),
        )
    try:
        target = validate_target(payload.host, payload.port, resolve=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    domain = monitoring_store.upsert_domain(
        host=target.host,
        port=target.port,
        scan_interval_seconds=payload.scan_interval_seconds,
        enabled=payload.enabled,
        notes=payload.notes.strip(),
    )
    return domain_to_dict(domain)


@app.get("/api/monitor/domains/{domain_id}/snapshots")
def list_monitor_snapshots(
    domain_id: int,
    limit: int = 20,
    x_monitoring_admin_token: str | None = Header(default=None),
) -> Dict[str, object]:
    require_monitoring_admin_token(x_monitoring_admin_token)
    snapshots = monitoring_store.list_snapshots(
        monitored_domain_id=domain_id,
        limit=max(1, min(limit, 200)),
    )
    return {"items": [snapshot_to_dict(item) for item in snapshots]}


@app.get("/api/monitor/domains/{domain_id}/events")
def list_monitor_events(
    domain_id: int,
    limit: int = 50,
    x_monitoring_admin_token: str | None = Header(default=None),
) -> Dict[str, object]:
    require_monitoring_admin_token(x_monitoring_admin_token)
    events = monitoring_store.list_events(
        monitored_domain_id=domain_id,
        limit=max(1, min(limit, 500)),
    )
    return {"items": [event_to_dict(item) for item in events]}


@app.get("/api/monitor/domains/{domain_id}/trend")
def monitor_domain_trend(
    domain_id: int,
    days: int = 90,
    x_monitoring_admin_token: str | None = Header(default=None),
) -> Dict[str, object]:
    require_monitoring_admin_token(x_monitoring_admin_token)
    snapshots = monitoring_store.list_snapshots(
        monitored_domain_id=domain_id,
        limit=max(10, min(days * 8, 2000)),
    )
    cutoff = datetime.now(timezone.utc).timestamp() - (max(1, min(days, 3650)) * 86400)
    points = []
    for item in reversed(snapshots):
        ts = None
        if item.created_at is not None and hasattr(item.created_at, "timestamp"):
            ts = item.created_at.timestamp()
        if ts is not None and ts < cutoff:
            continue
        points.append(
            {
                "snapshot_id": item.id,
                "created_at": iso_or_none(item.created_at),
                "grade": item.grade,
                "score": item.score,
                "critical_findings": len(
                    [f for f in item.findings if str(f.severity).lower() == "critical"]
                ),
                "high_findings": len(
                    [f for f in item.findings if str(f.severity).lower() == "high"]
                ),
            }
        )
    latest = points[-1] if points else None
    first = points[0] if points else None
    delta_score = None
    if latest and first and latest.get("score") is not None and first.get("score") is not None:
        delta_score = int(latest["score"]) - int(first["score"])
    return {
        "domain_id": domain_id,
        "days": days,
        "points": points,
        "summary": {
            "count": len(points),
            "latest_grade": latest.get("grade") if latest else None,
            "latest_score": latest.get("score") if latest else None,
            "score_delta": delta_score,
        },
    }


@app.patch("/api/monitor/domains/{domain_id}")
def patch_monitor_domain(
    domain_id: int,
    payload: MonitorDomainPatchRequest,
    x_monitoring_admin_token: str | None = Header(default=None),
) -> Dict[str, object]:
    require_monitoring_admin_token(x_monitoring_admin_token)
    if payload.scan_interval_seconds is not None and payload.scan_interval_seconds < MIN_SCAN_INTERVAL_SECONDS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Интервал мониторинга слишком маленький. "
                f"Минимум: {MIN_SCAN_INTERVAL_SECONDS} секунд."
            ),
        )
    domain = monitoring_store.update_domain(
        domain_id=domain_id,
        enabled=payload.enabled,
        scan_interval_seconds=payload.scan_interval_seconds,
        notes=payload.notes.strip() if payload.notes is not None else None,
    )
    if not domain:
        raise HTTPException(status_code=404, detail="Домен мониторинга не найден.")
    return domain_to_dict(domain)


@app.post("/api/monitor/domains/{domain_id}/scan-now")
def monitor_scan_now(
    domain_id: int,
    x_monitoring_admin_token: str | None = Header(default=None),
) -> Dict[str, object]:
    require_monitoring_admin_token(x_monitoring_admin_token)
    domain = monitoring_store.get_domain(domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Домен мониторинга не найден.")
    scheduled = schedule_domain_scan(
        domain=domain,
        monitoring_store=monitoring_store,
        job_store=job_store,
        enqueue_scan_job=enqueue_scan_job,
        archive_store=archive_store,
        target_scan_guard=target_scan_guard,
    )
    if isinstance(scheduled, dict):
        return {"status": "skipped", **scheduled}
    return {
        "status": scheduled.status,
        "domain_id": scheduled.domain_id,
        "host": scheduled.host,
        "port": scheduled.port,
        "job_id": scheduled.job_id,
    }


@app.post("/api/subscriptions/monitoring")
def create_monitor_subscription(payload: SubscribeRequest) -> Dict[str, object]:
    try:
        target = validate_target(payload.host, payload.port, resolve=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    email = payload.email.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=400, detail="Укажите корректный email.")
    plan = payload.plan.strip().lower()
    if plan == "pro":
        plan = "support"
    if plan not in {"free", "support"}:
        raise HTTPException(status_code=400, detail="Неизвестный план подписки.")
    account = billing_store.get_by_email(email)
    existing = [item for item in subscription_store.find_by_email(email) if item.enabled]
    same_target_exists = any(item.host == target.host and item.port == target.port for item in existing)
    if plan == "support":
        billed_limit = int(account.domain_limit) if account and account.plan == "support" and account.status == "active" else 10
        plan_limit = max(1, min(10, billed_limit))
    else:
        plan_limit = 1
    if len(existing) >= plan_limit and not same_target_exists:
        detail = (
            "Для бесплатного режима доступен мониторинг только одного домена на email."
            if plan == "free"
            else "Для плана Pro доступно до 10 доменов на email."
        )
        raise HTTPException(
            status_code=409,
            detail=detail,
        )
    sub = subscription_store.upsert_pending(
        host=target.host,
        port=target.port,
        email=email,
        plan=plan,
    )
    confirm_url = f"{settings.public_base_url}/api/subscriptions/monitoring/confirm?token={sub.token}"
    unsubscribe_url = f"{settings.public_base_url}/api/subscriptions/monitoring/unsubscribe?token={sub.token}"
    confirmation_sent = send_confirmation_email(
        email=sub.email,
        host=sub.host,
        plan=sub.plan,
        confirm_url=confirm_url,
        unsubscribe_url=unsubscribe_url,
    )
    return {
        "status": "pending_confirmation",
        "subscription_id": sub.id,
        "host": sub.host,
        "port": sub.port,
        "email": sub.email,
        "plan": sub.plan,
        "ownership_reused": bool(sub.plan == "support" and sub.ownership_verified_at is not None),
        "confirm_url": confirm_url,
        "unsubscribe_url": unsubscribe_url,
        "confirmation_sent": confirmation_sent,
    }


@app.get("/api/subscriptions/monitoring")
def list_monitor_subscriptions(token: str, limit: int = 20) -> Dict[str, object]:
    normalized = require_monitor_owner_token(token)
    items = subscription_store.list_by_email(normalized, limit=max(1, min(limit, 100)))
    domains = monitoring_store.list_domains(limit=1000) if getattr(monitoring_store, "enabled", False) else []
    domain_map = {(item.host, int(item.port)): item for item in domains}
    has_support = any(item.plan == "support" and item.enabled for item in items)
    account = billing_store.get_by_email(normalized)
    if account and account.plan == "support" and account.status == "active":
        effective_plan = "pro"
        effective_limit = max(10, int(account.domain_limit or 10))
    elif has_support:
        effective_plan = "pro"
        effective_limit = 10
    else:
        effective_plan = "free"
        effective_limit = 1
    return {
        "email": normalized,
        "plan": effective_plan,
        "domain_limit": effective_limit,
        "manage_token": token,
        "items": [
            subscription_item_to_dict(item, domain_map.get((item.host, int(item.port))))
            for item in items
        ],
    }


@app.delete("/api/subscriptions/monitoring/{subscription_id}")
def delete_monitor_subscription(subscription_id: int, token: str) -> Dict[str, object]:
    sub = require_subscription_owner(subscription_id, token)
    disabled = subscription_store.disable_by_id(sub.id)
    if not disabled:
        raise HTTPException(status_code=404, detail="Подписка не найдена.")
    return {
        "status": "disabled",
        "subscription_id": disabled.id,
        "host": disabled.host,
        "port": disabled.port,
    }


@app.get("/api/subscriptions/monitoring/events")
def list_monitor_subscription_events(token: str, limit: int = 30) -> Dict[str, object]:
    normalized = require_monitor_owner_token(token)
    items = subscription_store.list_by_email(normalized, limit=max(1, min(limit, 100)))
    domains = monitoring_store.list_domains(limit=1000) if getattr(monitoring_store, "enabled", False) else []
    domain_map = {(item.host, int(item.port)): item for item in domains}
    per_domain_limit = max(1, min(10, limit))
    result_items = []
    for sub in items:
        domain = domain_map.get((sub.host, int(sub.port)))
        events: list[dict[str, object]] = []
        if domain:
            events = [
                event_to_dict(item)
                for item in monitoring_store.list_events(domain.id, limit=per_domain_limit)
            ]
        result_items.append(
            {
                "subscription_id": sub.id,
                "host": sub.host,
                "port": sub.port,
                "plan": "pro" if sub.plan == "support" else sub.plan,
                "enabled": sub.enabled,
                "confirmed": sub.confirmed,
                "ownership_method": sub.ownership_method,
                "ownership_verified": sub.ownership_verified_at is not None,
                "events": events,
            }
        )
    return {"email": normalized, "items": result_items, "manage_token": token}


@app.get("/api/subscriptions/monitoring/export.json")
def export_monitoring_json(token: str, limit: int = 50, events_limit: int = 20) -> Dict[str, object]:
    normalized = require_monitor_owner_token(token)
    payload = build_monitoring_export_payload(
        normalized_email=normalized,
        token=token,
        limit=limit,
        events_limit=events_limit,
    )
    payload["format"] = "json"
    return payload


@app.get("/api/subscriptions/monitoring/export.csv")
def export_monitoring_csv(token: str, limit: int = 50, events_limit: int = 20) -> Response:
    normalized = require_monitor_owner_token(token)
    payload = build_monitoring_export_payload(
        normalized_email=normalized,
        token=token,
        limit=limit,
        events_limit=events_limit,
    )
    csv_text = monitoring_export_to_csv(payload)
    filename = f"tlsaudit-monitoring-{normalized.replace('@', '_at_')}.csv"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=csv_text, media_type="text/csv; charset=utf-8", headers=headers)


@app.get("/api/subscriptions/monitoring/digest.json")
def monitoring_digest_json(token: str, limit: int = 20, events_limit: int = 20) -> Dict[str, object]:
    normalized = require_monitor_owner_token(token)
    return build_monitoring_digest_payload(
        normalized_email=normalized,
        token=token,
        limit=limit,
        events_limit=events_limit,
    )


@app.get("/api/subscriptions/monitoring/confirm", response_class=HTMLResponse)
def confirm_monitor_subscription(token: str) -> HTMLResponse:
    sub = subscription_store.confirm(token)
    if not sub:
        body = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Подписка не найдена</title>
<style>
body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f4;margin:0;color:#1a1f2b}
.wrap{max-width:760px;margin:40px auto;padding:0 16px}
.card{background:#fff;border:1px solid #d7dbd7;border-radius:10px;padding:18px}
h1{margin:0 0 12px;font-size:30px} p{margin:8px 0} .muted{color:#5b6272} a{color:#0f766e}
</style></head><body><div class="wrap"><div class="card">
<h1>Ссылка недействительна</h1>
<p class="muted">Подписка не найдена, уже подтверждена или была отключена.</p>
<p><a href="/">Вернуться на главную</a></p>
</div></div></body></html>"""
        return HTMLResponse(content=body, status_code=404)
    plan_title = "Бесплатный" if sub.plan == "free" else "Pro (расширенный)"
    manage_url = (
        f"{settings.public_base_url}/monitor-status"
        f"?token={create_monitor_owner_token(sub.email)}"
    )
    body = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Подписка подтверждена</title>
<style>
body{{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f4;margin:0;color:#1a1f2b}}
.wrap{{max-width:760px;margin:40px auto;padding:0 16px}}
.card{{background:#fff;border:1px solid #d7dbd7;border-radius:10px;padding:18px}}
h1{{margin:0 0 12px;font-size:30px}} p{{margin:8px 0}} .muted{{color:#5b6272}}
a{{color:#0f766e}}
</style></head><body><div class="wrap"><div class="card">
<h1>Подписка подтверждена</h1>
<p><strong>Домен:</strong> {sub.host}</p>
<p><strong>Email:</strong> {sub.email}</p>
<p><strong>План:</strong> {plan_title}</p>
<p class="muted">Мониторинг активирован. Следующий отчёт придёт автоматически по расписанию.</p>
<p><a href="{manage_url}">Открыть приватное управление подпиской</a></p>
<p><a href="/">Вернуться на главную</a></p>
</div></div></body></html>"""
    return HTMLResponse(content=body)


@app.get("/api/subscriptions/monitoring/unsubscribe", response_class=HTMLResponse)
def unsubscribe_monitor_subscription(token: str) -> HTMLResponse:
    sub = subscription_store.disable(token)
    if not sub:
        body = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Подписка не найдена</title></head>
<body style="font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f4;margin:0;color:#1a1f2b">
<div style="max-width:760px;margin:40px auto;padding:0 16px">
<div style="background:#fff;border:1px solid #d7dbd7;border-radius:10px;padding:18px">
<h1 style="margin:0 0 12px;font-size:30px">Ссылка недействительна</h1>
<p style="color:#5b6272">Подписка не найдена или уже отключена.</p>
<p><a style="color:#0f766e" href="/">Вернуться на главную</a></p>
</div></div></body></html>"""
        return HTMLResponse(content=body, status_code=404)
    body = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Подписка отключена</title></head>
<body style="font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f5f4;margin:0;color:#1a1f2b">
<div style="max-width:760px;margin:40px auto;padding:0 16px">
<div style="background:#fff;border:1px solid #d7dbd7;border-radius:10px;padding:18px">
<h1 style="margin:0 0 12px;font-size:30px">Подписка отключена</h1>
<p><strong>Домен:</strong> {sub.host}</p>
<p><strong>Email:</strong> {sub.email}</p>
<p style="color:#5b6272">Автоматические письма больше не будут отправляться.</p>
<p><a href="/" style="color:#0f766e">Вернуться на главную</a></p>
</div></div></body></html>"""
    return HTMLResponse(content=body)


@app.post("/api/subscriptions/monitoring/{subscription_id}/run-now")
def run_monitor_subscription_now(subscription_id: int, token: str) -> Dict[str, object]:
    require_subscription_owner(subscription_id, token)
    from services.scheduler.scheduler import run_subscription_now

    result = run_subscription_now(subscription_id)
    if result["status"] == "not_found":
        raise HTTPException(status_code=404, detail="Подписка не найдена.")
    if result["status"] == "disabled":
        raise HTTPException(status_code=409, detail="Подписка отключена.")
    if result["status"] == "not_confirmed":
        raise HTTPException(status_code=409, detail="Подписка не подтверждена.")
    return result


@app.post("/api/subscriptions/monitoring/{subscription_id}/ownership/challenge")
def begin_subscription_ownership_challenge(
    subscription_id: int,
    payload: OwnershipChallengeRequest,
    token: str,
) -> Dict[str, object]:
    sub = require_subscription_owner(subscription_id, token)
    method = payload.method.strip().lower()
    if method not in {"dns_txt", "http_file"}:
        raise HTTPException(status_code=400, detail="Поддерживаются только dns_txt и http_file.")

    challenge = secrets.token_urlsafe(18)
    updated = subscription_store.begin_ownership_verification(
        subscription_id=sub.id,
        method=method,
        token=challenge,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Подписка не найдена.")

    if method == "dns_txt":
        return {
            "subscription_id": updated.id,
            "method": method,
            "host": updated.host,
            "token": challenge,
            "record_name": f"_tlsaudit-challenge.{updated.host}",
            "record_type": "TXT",
            "record_value": challenge,
            "instruction": (
                "Добавьте TXT запись и дождитесь её распространения в DNS, "
                "после чего нажмите Verify."
            ),
        }
    return {
        "subscription_id": updated.id,
        "method": method,
        "host": updated.host,
        "token": challenge,
        "file_url": ownership_http_url(updated.host),
        "file_content": challenge,
        "instruction": (
            "Создайте файл по указанному URL с указанным содержимым, "
            "после чего нажмите Verify."
        ),
    }


@app.get("/api/subscriptions/monitoring/{subscription_id}/ownership/status")
def get_subscription_ownership_status(subscription_id: int, token: str) -> Dict[str, object]:
    sub = require_subscription_owner(subscription_id, token)
    return {
        "subscription_id": sub.id,
        "host": sub.host,
        "plan": "pro" if sub.plan == "support" else sub.plan,
        "ownership_method": sub.ownership_method or "",
        "ownership_verified": sub.ownership_verified_at is not None,
        "ownership_verified_at": iso_or_none(sub.ownership_verified_at),
    }


@app.post("/api/subscriptions/monitoring/{subscription_id}/ownership/verify")
def verify_subscription_ownership(subscription_id: int, token: str) -> Dict[str, object]:
    sub = require_subscription_owner(subscription_id, token)
    if sub.plan != "support":
        return {
            "subscription_id": sub.id,
            "plan": "free",
            "ownership_required": False,
            "ownership_verified": True,
            "detail": "Для бесплатного плана отдельная ownership-проверка не требуется.",
        }
    if sub.ownership_verified_at is not None:
        return {
            "subscription_id": sub.id,
            "plan": "pro",
            "ownership_required": True,
            "ownership_verified": True,
            "ownership_verified_at": iso_or_none(sub.ownership_verified_at),
            "method": sub.ownership_method or "trusted_reuse",
            "detail": "Владение доменом уже подтверждено ранее для этого email.",
        }
    if not sub.ownership_method or not sub.ownership_token:
        raise HTTPException(
            status_code=409,
            detail="Сначала создайте challenge через /ownership/challenge.",
        )

    if sub.ownership_method == "dns_txt":
        ok, detail = verify_dns_txt(sub.host, sub.ownership_token)
    elif sub.ownership_method == "http_file":
        ok, detail = verify_http_file(sub.host, sub.ownership_token)
    else:
        raise HTTPException(status_code=400, detail="Неизвестный метод ownership-проверки.")

    if not ok:
        return {
            "subscription_id": sub.id,
            "host": sub.host,
            "ownership_verified": False,
            "method": sub.ownership_method,
            "detail": detail,
        }

    updated = subscription_store.mark_ownership_verified(sub.id)
    if not updated:
        raise HTTPException(status_code=404, detail="Подписка не найдена.")
    return {
        "subscription_id": updated.id,
        "host": updated.host,
        "ownership_verified": True,
        "ownership_verified_at": iso_or_none(updated.ownership_verified_at),
        "method": updated.ownership_method,
        "detail": detail,
    }


def request_ip(request: Request) -> str:
    if settings.trust_proxy_headers:
        forwarded_for = request.headers.get("x-forwarded-for", "")
        candidate = forwarded_for.split(",", 1)[0].strip()
        if candidate:
            return candidate
    return request.client.host if request.client else "unknown"


def admission_error(
    status_code: int,
    message: str,
    decision: AdmissionDecision,
) -> HTTPException:
    detail: Dict[str, object] = {"message": message}
    headers = {}
    if decision.retry_after:
        detail["retry_after"] = decision.retry_after
        headers["Retry-After"] = str(decision.retry_after)
    if decision.captcha_required:
        detail["captcha_required"] = True
    if decision.job_id:
        detail["job_id"] = decision.job_id
    return HTTPException(status_code=status_code, detail=detail, headers=headers)


def domain_to_dict(domain) -> Dict[str, object]:
    return {
        "id": domain.id,
        "host": domain.host,
        "port": domain.port,
        "enabled": domain.enabled,
        "scan_interval_seconds": domain.scan_interval_seconds,
        "last_scan_at": iso_or_none(domain.last_scan_at),
        "next_scan_at": iso_or_none(domain.next_scan_at),
        "notes": domain.notes,
    }


def subscription_item_to_dict(item, domain) -> Dict[str, object]:
    latest_scan_id = None
    monitored_domain_id = None
    certificate_expires_in_days = None
    last_scan_at = None
    if domain:
        monitored_domain_id = domain.id
        last_scan_at = iso_or_none(getattr(domain, "last_scan_at", None))
        latest_events = monitoring_store.list_events(domain.id, limit=1)
        if latest_events:
            latest_scan_id = latest_events[0].get("scan_id")
        latest_snapshot = monitoring_store.latest_snapshot(domain.id)
        if latest_snapshot:
            certificate_expires_in_days = latest_snapshot.certificate_expires_in_days
    ownership_ok = item.ownership_verified_at is not None
    pro_delivery_ready = item.plan != "support" or ownership_ok
    delivery_status = "active" if pro_delivery_ready else "paused_ownership"
    return {
        "id": item.id,
        "host": item.host,
        "port": item.port,
        "token": item.token,
        "plan": "pro" if item.plan == "support" else item.plan,
        "enabled": item.enabled,
        "confirmed": item.confirmed,
        "ownership_method": item.ownership_method,
        "ownership_verified": item.ownership_verified_at is not None,
        "ownership_verified_at": iso_or_none(item.ownership_verified_at),
        "ownership_reused": bool(item.ownership_method == "trusted_reuse"),
        "pro_delivery_ready": pro_delivery_ready,
        "delivery_status": delivery_status,
        "last_sent_at": iso_or_none(item.last_sent_at),
        "next_run_at": iso_or_none(item.next_run_at),
        "created_at": iso_or_none(item.created_at),
        "monitored_domain_id": monitored_domain_id,
        "certificate_expires_in_days": certificate_expires_in_days,
        "last_scan_at": last_scan_at,
        "latest_scan_id": latest_scan_id,
    }


def snapshot_to_dict(snapshot) -> Dict[str, object]:
    return {
        "id": snapshot.id,
        "monitored_domain_id": snapshot.monitored_domain_id,
        "scan_id": snapshot.scan_id,
        "grade": snapshot.grade,
        "score": snapshot.score,
        "certificate_not_after": snapshot.certificate_not_after,
        "certificate_expires_in_days": snapshot.certificate_expires_in_days,
        "supported_protocols": snapshot.supported_protocols,
        "hsts": snapshot.hsts,
        "findings": [finding.to_dict() for finding in snapshot.findings],
        "created_at": iso_or_none(snapshot.created_at),
    }


def event_to_dict(event: Dict[str, object]) -> Dict[str, object]:
    return {
        **event,
        "created_at": iso_or_none(event.get("created_at")),
    }


def iso_or_none(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def build_monitoring_export_payload(
    normalized_email: str,
    token: str,
    limit: int = 50,
    events_limit: int = 20,
) -> Dict[str, object]:
    items = subscription_store.list_by_email(normalized_email, limit=max(1, min(limit, 100)))
    domains = monitoring_store.list_domains(limit=1000) if getattr(monitoring_store, "enabled", False) else []
    domain_map = {(item.host, int(item.port)): item for item in domains}
    per_domain_limit = max(1, min(50, int(events_limit)))
    export_items: List[Dict[str, object]] = []
    for sub in items:
        domain = domain_map.get((sub.host, int(sub.port)))
        events: List[Dict[str, object]] = []
        if domain:
            events = [
                event_to_dict(item)
                for item in monitoring_store.list_events(domain.id, limit=per_domain_limit)
            ]
        export_items.append(
            {
                "subscription_id": sub.id,
                "host": sub.host,
                "port": sub.port,
                "plan": "pro" if sub.plan == "support" else sub.plan,
                "enabled": sub.enabled,
                "confirmed": sub.confirmed,
                "ownership_method": sub.ownership_method,
                "ownership_verified": sub.ownership_verified_at is not None,
                "last_sent_at": iso_or_none(sub.last_sent_at),
                "next_run_at": iso_or_none(sub.next_run_at),
                "events": events,
            }
        )
    return {
        "email": normalized_email,
        "generated_at": iso_or_none(datetime.now(timezone.utc)),
        "manage_token": token,
        "items": export_items,
    }


def build_monitoring_digest_payload(
    normalized_email: str,
    token: str,
    limit: int = 20,
    events_limit: int = 20,
) -> Dict[str, object]:
    payload = build_monitoring_export_payload(
        normalized_email=normalized_email,
        token=token,
        limit=limit,
        events_limit=events_limit,
    )
    base_url = settings.public_base_url.rstrip("/")
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    digest_items: List[Dict[str, object]] = []
    for item in payload.get("items", []):
        if not isinstance(item, dict):
            continue
        events = item.get("events") or []
        normalized_events: List[Dict[str, object]] = []
        for event in events:
            if not isinstance(event, dict):
                continue
            sev = str(event.get("severity") or "info").lower()
            scan_id = str(event.get("scan_id") or "").strip()
            normalized_events.append(
                {
                    "event_type": event.get("event_type"),
                    "severity": sev,
                    "title": event.get("title"),
                    "detail": event.get("detail"),
                    "created_at": event.get("created_at"),
                    "scan_id": scan_id or None,
                    "scan_url": f"{base_url}/scan?job={scan_id}" if scan_id else None,
                    "diff_url": f"{base_url}/api/report/{scan_id}/compare" if scan_id else None,
                }
            )
        normalized_events.sort(
            key=lambda entry: (
                severity_rank.get(str(entry.get("severity") or "info"), 9),
                str(entry.get("created_at") or ""),
            ),
        )
        top_events = normalized_events[:5]
        critical_high = [
            event
            for event in normalized_events
            if str(event.get("severity") or "").lower() in {"critical", "high"}
        ]
        latest_scan_id = None
        for event in normalized_events:
            value = event.get("scan_id")
            if value:
                latest_scan_id = str(value)
                break
        digest_items.append(
            {
                "subscription_id": item.get("subscription_id"),
                "host": item.get("host"),
                "port": item.get("port"),
                "plan": item.get("plan"),
                "delivery_status": "paused_ownership"
                if item.get("plan") == "pro" and not item.get("ownership_verified")
                else "active",
                "ownership_verified": item.get("ownership_verified"),
                "last_sent_at": item.get("last_sent_at"),
                "next_run_at": item.get("next_run_at"),
                "critical_high_count": len(critical_high),
                "top_events": top_events,
                "latest_scan_id": latest_scan_id,
                "latest_scan_url": (f"{base_url}/scan?job={latest_scan_id}" if latest_scan_id else None),
                "latest_diff_url": (f"{base_url}/api/report/{latest_scan_id}/compare" if latest_scan_id else None),
            }
        )
    return {
        "email": normalized_email,
        "generated_at": payload.get("generated_at"),
        "manage_url": f"{base_url}/monitor-status?token={token}",
        "items": digest_items,
    }




def send_confirmation_email(
    *,
    email: str,
    host: str,
    plan: str,
    confirm_url: str,
    unsubscribe_url: str,
) -> bool:
    plan_norm = str(plan or "free").strip().lower()
    if plan_norm == "support":
        plan_title = "Pro ($10/мес, до 10 доменов)"
    else:
        plan_title = "бесплатный (1 домен)"
    subject = f"TLS Audit: подтвердите подписку для {host}"
    body = (
        f"Вы запросили подписку на мониторинг для {host}.\n"
        f"План: {plan_title}.\n\n"
        f"Подтвердить подписку: {confirm_url}\n"
        f"Отключить подписку: {unsubscribe_url}\n\n"
        "Если это были не вы, просто проигнорируйте письмо."
    )
    smtp_url = os.getenv("SMTP_URL", "").strip()
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    mail_from = os.getenv("ALERT_EMAIL_FROM", "tls-audit@localhost").strip()
    if not smtp_url:
        log_event(
            logger,
            "subscription_confirmation_email_skipped",
            email=email,
            host=host,
            reason="smtp_not_configured",
            subject=subject,
            body=body,
        )
        return False
    try:
        return send_email(
            smtp_url=smtp_url,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            mail_from=mail_from,
            mail_to=email,
            subject=subject,
            body=body,
        )
    except Exception as exc:  # noqa: BLE001
        log_event(
            logger,
            "subscription_confirmation_email_failed",
            email=email,
            host=host,
            error=str(exc),
        )
        return False

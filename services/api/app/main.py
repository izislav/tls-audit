import logging
from datetime import datetime, timezone
from typing import Dict

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - installed in Docker/runtime.
    raise RuntimeError(
        "FastAPI dependencies are not installed. Install requirements/api.txt."
    ) from exc

from shared.tls_audit.validation import validate_target
from shared.tls_audit.compare import compare_reports, summarize_report
from shared.tls_audit.logging import log_event
from shared.tls_audit.traffic_control import AdmissionDecision

from .archive import archive_store
from .denylist import denylist
from .frontend import STATIC_PAGES, render_frontend, render_static_page
from .jobs import job_store
from .monitoring import monitoring_store
from .queue import enqueue_scan_job, queue_depth
from .rate_limit import rate_limiter
from .settings import settings
from .target_guard import target_scan_guard
from shared.tls_audit.monitoring_store import (
    DEFAULT_SCAN_INTERVAL_SECONDS,
    MIN_SCAN_INTERVAL_SECONDS,
)
from shared.tls_audit.monitoring_scheduler import schedule_domain_scan


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("tls_audit.api")


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


@app.get("/health")
def health() -> Dict[str, str]:
    return {
        "status": "ok",
        "database": "enabled" if archive_store.enabled else "disabled",
    }


@app.get("/", response_class=HTMLResponse)
def frontend() -> str:
    return render_frontend()


@app.head("/")
def frontend_head() -> Response:
    return Response()


@app.get("/scan", response_class=HTMLResponse)
def scan_frontend() -> str:
    return render_frontend()


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
def list_monitor_domains(limit: int = 100) -> Dict[str, object]:
    domains = monitoring_store.list_domains(limit=max(1, min(limit, 500)))
    return {"items": [domain_to_dict(item) for item in domains]}


@app.post("/api/monitor/domains")
def upsert_monitor_domain(payload: MonitorDomainRequest) -> Dict[str, object]:
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
def list_monitor_snapshots(domain_id: int, limit: int = 20) -> Dict[str, object]:
    snapshots = monitoring_store.list_snapshots(
        monitored_domain_id=domain_id,
        limit=max(1, min(limit, 200)),
    )
    return {"items": [snapshot_to_dict(item) for item in snapshots]}


@app.get("/api/monitor/domains/{domain_id}/events")
def list_monitor_events(domain_id: int, limit: int = 50) -> Dict[str, object]:
    events = monitoring_store.list_events(
        monitored_domain_id=domain_id,
        limit=max(1, min(limit, 500)),
    )
    return {"items": [event_to_dict(item) for item in events]}


@app.patch("/api/monitor/domains/{domain_id}")
def patch_monitor_domain(domain_id: int, payload: MonitorDomainPatchRequest) -> Dict[str, object]:
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
def monitor_scan_now(domain_id: int) -> Dict[str, object]:
    domain = monitoring_store.get_domain(domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Домен мониторинга не найден.")
    scheduled = schedule_domain_scan(
        domain=domain,
        monitoring_store=monitoring_store,
        job_store=job_store,
        enqueue_scan_job=enqueue_scan_job,
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

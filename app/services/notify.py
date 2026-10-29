import logging
import smtplib
from email.message import EmailMessage

import requests

from ..config import Config
from ..db import get_db
from ..plans import feature
from ..utils import now

log = logging.getLogger("siteguard.notify")

DEFAULT_SETTINGS = {
    "emails": [],
    "slack_webhook": "",
    "teams_webhook": "",
    "webhook_url": "",
    "events": {
        "incident_opened": True,
        "incident_resolved": True,
        "incident_reopened": True,
        "escalation": True,
        "visual_change": True,
        "report_ready": True,
    },
    "min_severity": "minor",
    "escalation": {"enabled": False, "after_minutes": 30, "emails": []},
    "quiet_hours": {"enabled": False, "start": "22:00", "end": "07:00"},
}

SEVERITY_RANK = {"info": 0, "minor": 1, "major": 2, "critical": 3}


def settings_for(ws: dict) -> dict:
    s = {**DEFAULT_SETTINGS, **(ws.get("notifications") or {})}
    s["events"] = {**DEFAULT_SETTINGS["events"], **(s.get("events") or {})}
    s["escalation"] = {**DEFAULT_SETTINGS["escalation"], **(s.get("escalation") or {})}
    s["quiet_hours"] = {**DEFAULT_SETTINGS["quiet_hours"], **(s.get("quiet_hours") or {})}
    return s


def _in_quiet_hours(s: dict) -> bool:
    q = s.get("quiet_hours") or {}
    if not q.get("enabled"):
        return False
    try:
        start_h, start_m = [int(x) for x in str(q.get("start") or "22:00").split(":")[:2]]
        end_h, end_m = [int(x) for x in str(q.get("end") or "07:00").split(":")[:2]]
    except (TypeError, ValueError):
        return False
    t = now()
    mins = t.hour * 60 + t.minute
    start, end = start_h * 60 + start_m, end_h * 60 + end_m
    if start == end:
        return False
    if start < end:
        return start <= mins < end
    return mins >= start or mins < end


def _slack_blocks(subject: str, body: str, *, severity: str, event: str, link: str | None) -> dict:
    color = {"critical": "#d64545", "major": "#9b1b67", "minor": "#5b8def", "info": "#6b7280"}.get(severity, "#9b1b67")
    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
        {"type": "mrkdwn", "text": f"*Event*\n{event.replace('_', ' ')}"},
    ]
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": subject[:140], "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": body[:2800]}},
        {"type": "section", "fields": fields},
    ]
    if link:
        blocks.append({"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Open in SiteGuard"}, "url": link, "style": "primary"}
        ]})
    return {
        "text": f"{subject}\n{body}",
        "attachments": [{"color": color, "blocks": blocks}],
    }


def _record(ws_id, channel, target, subject, status, error=None, incident_id=None, event=None):
    get_db().notifications.insert_one({
        "workspace_id": ws_id, "incident_id": incident_id, "event": event, "channel": channel,
        "target": target, "subject": subject, "status": status, "error": error, "at": now(),
    })


def send_email(to: list[str], subject: str, body: str, html: str | None = None) -> tuple[str, str | None]:
    if not to:
        return "skipped", "no recipients"
    if not Config.SMTP_HOST:
        log.info("[email:logged] to=%s subject=%s\n%s", to, subject, body)
        return "logged", None
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = Config.SMTP_FROM
    msg["To"] = ", ".join(to)
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    try:
        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=15) as s:
            if Config.SMTP_TLS:
                s.starttls()
            if Config.SMTP_USER:
                s.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
            s.send_message(msg)
        return "sent", None
    except Exception as e:  # noqa: BLE001
        log.warning("email failed: %s", e)
        return "failed", str(e)


def _post(url: str, payload: dict) -> tuple[str, str | None]:
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code >= 400:
            return "failed", f"HTTP {r.status_code}"
        return "sent", None
    except requests.RequestException as e:
        return "failed", str(e)


def dispatch(ws: dict, event: str, subject: str, body: str, *, severity: str = "major",
             incident_id=None, link: str | None = None, extra_emails: list[str] | None = None) -> None:
    s = settings_for(ws)
    if not s["events"].get(event, True) and event != "escalation":
        return
    if event in ("incident_opened", "incident_reopened") and SEVERITY_RANK.get(severity, 2) < SEVERITY_RANK.get(s["min_severity"], 1):
        return
    # Quiet hours mute non-critical, non-escalation noise so agencies/startups can sleep.
    if event != "escalation" and severity != "critical" and _in_quiet_hours(s):
        _record(ws["_id"], "quiet_hours", "suppressed", subject, "skipped", "quiet hours", incident_id, event)
        return
    full_body = body + (f"\n\nOpen in SiteGuard: {link}" if link else "")
    emails = extra_emails if extra_emails is not None else s["emails"]
    if not emails:
        owner_emails = [m["email"] for m in get_db().members.find({"workspace_id": ws["_id"], "role": "owner", "status": "active"})]
        emails = owner_emails
    status, err = send_email(emails, f"[SiteGuard] {subject}", full_body)
    _record(ws["_id"], "email", ", ".join(emails), subject, status, err, incident_id, event)

    text = f"*{subject}*\n{body}" + (f"\n<{link}|Open in SiteGuard>" if link else "")
    if s.get("slack_webhook") and feature(ws, "slack"):
        status, err = _post(s["slack_webhook"], _slack_blocks(subject, body, severity=severity, event=event, link=link))
        _record(ws["_id"], "slack", "slack webhook", subject, status, err, incident_id, event)
    if s.get("teams_webhook") and feature(ws, "slack"):
        status, err = _post(s["teams_webhook"], {"text": text})
        _record(ws["_id"], "teams", "teams webhook", subject, status, err, incident_id, event)
    if s.get("webhook_url"):
        status, err = _post(s["webhook_url"], {"event": event, "subject": subject, "body": body,
                                               "severity": severity, "incident_id": str(incident_id) if incident_id else None,
                                               "link": link, "at": now().isoformat()})
        _record(ws["_id"], "webhook", s["webhook_url"], subject, status, err, incident_id, event)

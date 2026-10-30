import html as html_lib
import logging
import mimetypes
import smtplib
from email.message import EmailMessage
from pathlib import Path

import requests

from ..config import Config
from ..db import get_db
from ..plans import feature
from ..utils import now

log = logging.getLogger("watchfront.notify")

_EMAIL_STATIC = Path(__file__).resolve().parent.parent / "static" / "email"

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

KIND_LABELS = {
    "js_errors": "JavaScript error",
    "rum_api": "API failure (visitors)",
    "website": "Uptime / HTTP",
    "ssl": "SSL certificate",
    "domain": "Domain expiry",
    "api": "API monitor",
    "browser_test": "User journey",
    "page_check": "Content / visual check",
    "visual_change": "Visual change",
    "seo": "SEO audit",
    "escalation": "Escalation",
    "incident_resolved": "Recovered",
}


def _esc(v) -> str:
    return html_lib.escape("" if v is None else str(v))


def email_asset(name: str, *, inline: bool = True) -> str:
    """URL for email GIFs/heroes. Prefer cid: so clients render without a remote fetch."""
    name = name.lstrip("/")
    if inline and (_EMAIL_STATIC / name).is_file():
        return f"cid:{name}"
    base = (Config.PUBLIC_API_URL or Config.APP_URL).rstrip("/")
    return f"{base}/email/{name}"


def _inline_cids_from_html(html: str) -> list[str]:
    """Collect cid: filenames referenced in HTML that exist in static/email."""
    found: list[str] = []
    needle = 'src="cid:'
    start = 0
    while True:
        i = html.find(needle, start)
        if i < 0:
            break
        j = html.find('"', i + len(needle))
        if j < 0:
            break
        name = html[i + len(needle):j]
        if name and name not in found and (_EMAIL_STATIC / name).is_file():
            found.append(name)
        start = j + 1
    return found


def _email_shell(*, accent: str, body_html: str, preheader: str = "") -> str:
    pre = (
        f'<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">{_esc(preheader)}</div>'
        if preheader else ""
    )
    return f"""\
<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#faf6ed">
{pre}
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#faf6ed;padding:28px 16px">
  <div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:22px;overflow:hidden;border:1px solid rgba(75,36,64,0.10);box-shadow:0 8px 30px rgba(28,15,24,0.06)">
    <div style="height:4px;background:{accent}"></div>
    {body_html}
  </div>
  <p style="max-width:560px;margin:16px auto 0;text-align:center;font-size:10px;font-weight:400;color:#9a8793;line-height:1.5">
    Watchfront · website monitoring for agencies<br/>
    <a href="{_esc(Config.APP_URL)}" style="color:#9b1b67;text-decoration:none;font-weight:400">{_esc(Config.APP_URL)}</a>
  </p>
</div>
</body></html>
"""


def _kind_tag(kind: str | None) -> str:
    if not kind:
        return ""
    if kind == "js_errors":
        return "JS"
    if kind == "rum_api":
        return "API"
    if kind in ("ssl", "domain"):
        return kind.upper()
    if kind == "browser_test":
        return "Journey"
    if kind == "website":
        return "Uptime"
    return None


def alert_subject(subject: str, *, severity: str = "major", kind: str | None = None) -> str:
    """Distinct subject prefixes so inboxes can assign custom notification sounds via rules."""
    sev = (severity or "major").capitalize()
    tag = _kind_tag(kind)
    if tag:
        return f"[Watchfront · {sev} · {tag}] {subject}"
    return f"[Watchfront · {sev}] {subject}"


def attention_html(
    *,
    title: str,
    body: str,
    severity: str = "major",
    event: str = "incident_opened",
    kind: str | None = None,
    site: str | None = None,
    link: str | None = None,
) -> str:
    """Dashboard-style attention card for alert emails (animated GIF header where supported)."""
    colors = {
        "critical": ("#d64545", "#fde8e8"),
        "major": ("#9b1b67", "#f8e8f1"),
        "minor": ("#5b8def", "#eaf1fc"),
        "info": ("#6b7280", "#f3f4f6"),
    }
    accent, wash = colors.get(severity, colors["major"])
    kind_label = KIND_LABELS.get(kind or "", (kind or event or "Alert").replace("_", " ").title())
    rows = [
        ("Severity", severity.upper()),
        ("Type", kind_label),
    ]
    if site:
        rows.append(("Website", site))
    rows.append(("When", now().strftime("%d %b %Y, %H:%M UTC")))

    kv = "".join(
        f'<tr><td style="padding:5px 0;color:#6b5a66;font-size:11px;font-weight:400;width:88px">{_esc(k)}</td>'
        f'<td style="padding:5px 0;color:#1c0f18;font-size:12px;font-weight:400">{_esc(v)}</td></tr>'
        for k, v in rows
    )
    cta = ""
    if link:
        cta = (
            f'<a href="{_esc(link)}" style="display:inline-block;margin-top:16px;background:#4b2440;'
            f'color:#faf6ed;text-decoration:none;padding:10px 18px;border-radius:999px;font-size:13px;'
            f'font-weight:500">Open in Watchfront</a>'
        )
    gif = email_asset("alert.gif")
    inner = f"""\
<img src="{_esc(gif)}" width="560" alt="Needs attention" style="display:block;width:100%;max-width:560px;height:auto;border:0"/>
<div style="padding:20px 22px 26px">
  <div style="display:inline-block;background:{wash};color:{accent};font-size:10px;font-weight:500;letter-spacing:0.06em;text-transform:uppercase;padding:3px 9px;border-radius:999px">Needs attention</div>
  <h1 style="margin:12px 0 0;font-size:17px;line-height:1.35;color:#1c0f18;font-weight:500">{_esc(title)}</h1>
  <p style="margin:8px 0 0;font-size:13px;line-height:1.55;font-weight:400;color:#5e3a54">{_esc(body)}</p>
  <table style="width:100%;margin-top:14px;border-collapse:collapse">{kv}</table>
  {cta}
  <p style="margin:16px 0 0;font-size:10px;font-weight:400;color:#9a8793">Reply to this email if you need a hand.</p>
</div>
"""
    return _email_shell(accent=accent, body_html=inner, preheader=f"{severity.upper()}: {title}")



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
            {"type": "button", "text": {"type": "plain_text", "text": "Open in Watchfront"}, "url": link, "style": "primary"}
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


def send_email(
    to: list[str],
    subject: str,
    body: str,
    html: str | None = None,
    *,
    severity: str | None = None,
    headers: dict | None = None,
) -> tuple[str, str | None]:
    if not to:
        return "skipped", "no recipients"
    if not Config.SMTP_HOST:
        log.info("[email:logged] to=%s subject=%s\n%s", to, subject, body)
        return "logged", None
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = Config.SMTP_FROM
    msg["To"] = ", ".join(to)
    # Help clients / rules flag urgency (and drive custom notification sounds via inbox filters).
    sev = (severity or "").lower()
    if sev == "critical":
        msg["Importance"] = "high"
        msg["X-Priority"] = "1"
        msg["Priority"] = "urgent"
    elif sev == "major":
        msg["Importance"] = "high"
        msg["X-Priority"] = "2"
    if severity:
        msg["X-Watchfront-Severity"] = severity
    for k, v in (headers or {}).items():
        if v is not None:
            msg[k] = str(v)
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
        # Attach animated GIFs / heroes referenced as cid:… so Gmail/Outlook show motion
        # without depending on a remote CDN fetch (many clients block remote images).
        html_part = msg.get_payload()[-1]
        for name in _inline_cids_from_html(html):
            path = _EMAIL_STATIC / name
            data = path.read_bytes()
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            maintype, subtype = ctype.split("/", 1)
            html_part.add_related(data, maintype=maintype, subtype=subtype, cid=name)
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


def send_welcome_email(user: dict) -> tuple[str, str | None]:
    """Startup-grade welcome + onboarding email after signup."""
    name = (user.get("name") or "").strip() or "there"
    email = user.get("email") or ""
    app = Config.APP_URL.rstrip("/")
    gif = email_asset("welcome.gif")
    subject = f"{name}, welcome aboard Watchfront — your portfolio just got a pulse"
    text = (
        f"Hi {name},\n\n"
        "You just joined Watchfront — the monitoring desk built for agencies that can't afford to hear about downtime from a client.\n\n"
        "Your 24-hour free trial is live. Here's how to feel the product in the next 10 minutes:\n"
        f"  1. Open the dashboard → {app}/app\n"
        "  2. Add a client website (or bulk-import a CSV)\n"
        "  3. Turn on email alerts — we'll ping you with a clear “needs attention” card\n"
        "  4. Optional: drop the browser script for real-visitor JS errors\n\n"
        "We don't promise zero downtime. We promise you'll know first — with evidence.\n\n"
        f"Start monitoring: {app}/app\n"
        f"Book a call if you're an agency with 10+ sites: {app}/contact#book\n\n"
        "Glad you're here,\n"
        "The Watchfront team\n"
    )
    steps = [
        ("1", "Add a website", "Paste a URL — first check lands in about a minute."),
        ("2", "Wire alerts", "Tell us who should get woken up (and who shouldn't)."),
        ("3", "Catch real bugs", "Optional script: JS crashes & failed APIs from real visitors."),
    ]
    steps_html = "".join(
        f"""<tr>
          <td style="padding:8px 0;vertical-align:top;width:32px">
            <div style="width:24px;height:24px;border-radius:999px;background:#f8e8f1;color:#9b1b67;font-weight:500;font-size:11px;line-height:24px;text-align:center">{n}</div>
          </td>
          <td style="padding:8px 0 8px 8px;vertical-align:top">
            <div style="font-size:13px;font-weight:500;color:#1c0f18">{_esc(title)}</div>
            <div style="font-size:12px;font-weight:400;color:#5e3a54;margin-top:2px">{_esc(body)}</div>
          </td>
        </tr>"""
        for n, title, body in steps
    )
    inner = f"""\
<a href="{_esc(app)}/app" style="display:block;text-decoration:none">
  <img src="{_esc(gif)}" width="560" alt="Watchfront — know before your clients do"
       style="display:block;width:100%;max-width:560px;height:auto;border:0"/>
</a>
<div style="padding:22px 24px 28px">
  <p style="margin:0;font-size:10px;font-weight:500;letter-spacing:0.1em;text-transform:uppercase;color:#9b1b67">You're in</p>
  <h1 style="margin:8px 0 0;font-size:20px;line-height:1.3;color:#1c0f18;font-weight:500">
    Hi {_esc(name)} — your monitoring desk is ready.
  </h1>
  <p style="margin:12px 0 0;font-size:13px;line-height:1.55;font-weight:400;color:#5e3a54">
    Built for agencies that manage other people's websites. Add sites, get evidence-backed alerts,
    and look sharp when something breaks — before the client Slack message arrives.
  </p>
  <p style="margin:16px 0 0">
    <a href="{_esc(app)}/app" style="display:inline-block;background:#4b2440;color:#faf6ed;padding:10px 18px;border-radius:999px;text-decoration:none;font-size:13px;font-weight:500">
      Open your dashboard →
    </a>
  </p>
  <p style="margin:22px 0 6px;font-size:12px;font-weight:500;color:#1c0f18">Your first 10 minutes</p>
  <table style="width:100%;border-collapse:collapse">{steps_html}</table>
  <div style="margin-top:18px;padding:14px 16px;border-radius:14px;background:#faf6ed;border:1px solid rgba(75,36,64,0.08)">
    <div style="font-size:12px;font-weight:500;color:#1c0f18">24-hour free trial</div>
    <div style="margin-top:3px;font-size:12px;line-height:1.5;font-weight:400;color:#5e3a54">
      Full Growth features today. If it earns its place, unlock a plan for another 30 days of access.
      No card required to start.
    </div>
  </div>
  <p style="margin:18px 0 0;font-size:12px;line-height:1.55;font-weight:400;color:#5e3a54">
    Questions, agency pricing, or 10+ sites?
    <a href="{_esc(app)}/contact#book" style="color:#9b1b67;font-weight:500">Book a call</a>
    — a human replies.
  </p>
  <p style="margin:20px 0 0;font-size:12px;font-weight:400;color:#1c0f18">
    Glad you're here,<br/>
    <span style="color:#5e3a54">The Watchfront team</span>
  </p>
</div>
"""
    html = _email_shell(
        accent="#9b1b67",
        body_html=inner,
        preheader="Your Watchfront trial is live — add a site and see your first check in about a minute.",
    )
    status, err = send_email([email], subject, text, html=html)
    if status != "sent":
        log.warning("welcome email to %s: %s %s", email, status, err)
    else:
        log.info("welcome email sent to %s", email)
    return status, err


def send_invite_email(
    *,
    to_email: str,
    workspace_name: str,
    inviter_name: str,
    role: str,
    has_account: bool,
) -> tuple[str, str | None]:
    """Team join invite — animated header + clear CTA."""
    app = Config.APP_URL.rstrip("/")
    gif = email_asset("welcome.gif")
    path = "login" if has_account else "register"
    cta_url = f"{app}/{path}"
    cta_label = "Sign in to join →" if has_account else "Create your account →"
    role_label = (role or "member").replace("_", " ").title()
    subject = f"You're invited to {workspace_name} on Watchfront"
    text = (
        f"{inviter_name} invited you to join {workspace_name} on Watchfront as {role_label}.\n\n"
        f"{'Sign in' if has_account else 'Create an account with this email'} at {cta_url}\n\n"
        "Watchfront is the monitoring desk for agencies — know before your clients do.\n"
    )
    inner = f"""\
<img src="{_esc(gif)}" width="560" alt="You're invited to Watchfront"
     style="display:block;width:100%;max-width:560px;height:auto;border:0"/>
<div style="padding:22px 24px 28px">
  <p style="margin:0;font-size:10px;font-weight:500;letter-spacing:0.1em;text-transform:uppercase;color:#9b1b67">Team invite</p>
  <h1 style="margin:8px 0 0;font-size:18px;line-height:1.3;color:#1c0f18;font-weight:500">
    {_esc(inviter_name)} wants you on {_esc(workspace_name)}.
  </h1>
  <p style="margin:12px 0 0;font-size:13px;line-height:1.55;font-weight:400;color:#5e3a54">
    You've been invited as <span style="color:#1c0f18">{_esc(role_label)}</span>.
    Join the desk, see client sites in one place, and catch issues before Slack blows up.
  </p>
  <p style="margin:16px 0 0">
    <a href="{_esc(cta_url)}" style="display:inline-block;background:#4b2440;color:#faf6ed;padding:10px 18px;border-radius:999px;text-decoration:none;font-size:13px;font-weight:500">
      {_esc(cta_label)}
    </a>
  </p>
  <p style="margin:18px 0 0;font-size:12px;line-height:1.5;font-weight:400;color:#9a8793">
    Use <span style="color:#5e3a54">{_esc(to_email)}</span> — the invite is tied to this address.
  </p>
</div>
"""
    html = _email_shell(
        accent="#9b1b67",
        body_html=inner,
        preheader=f"{inviter_name} invited you to {workspace_name} on Watchfront.",
    )
    return send_email([to_email], subject, text, html=html)


def book_call_html(*, name: str, topic: str, slot: str, note: str = "") -> str:
    """Animated confirmation for booked discovery calls."""
    app = Config.APP_URL.rstrip("/")
    gif = email_asset("welcome.gif")
    note_block = (
        f'<p style="margin:10px 0 0;font-size:12px;font-weight:400;color:#5e3a54"><span style="color:#1c0f18">Note:</span> {_esc(note)}</p>'
        if note else ""
    )
    inner = f"""\
<img src="{_esc(gif)}" width="560" alt="Call confirmed"
     style="display:block;width:100%;max-width:560px;height:auto;border:0"/>
<div style="padding:22px 24px 28px">
  <p style="margin:0;font-size:10px;font-weight:500;letter-spacing:0.1em;text-transform:uppercase;color:#9b1b67">You're booked</p>
  <h1 style="margin:8px 0 0;font-size:18px;line-height:1.3;color:#1c0f18;font-weight:500">
    Hi {_esc(name)} — talk soon.
  </h1>
  <p style="margin:12px 0 0;font-size:13px;line-height:1.55;font-weight:400;color:#5e3a54">
    Thanks for booking a call with Watchfront. We'll cover your portfolio, alert setup, and what Growth looks like for an agency desk.
  </p>
  <table style="width:100%;margin-top:14px;border-collapse:collapse;background:#faf6ed;border-radius:14px">
    <tr><td style="padding:12px 14px">
      <div style="font-size:10px;color:#9a8793;text-transform:uppercase;letter-spacing:0.06em;font-weight:500">When</div>
      <div style="margin-top:3px;font-size:14px;font-weight:500;color:#1c0f18">{_esc(slot)}</div>
      <div style="margin-top:10px;font-size:10px;color:#9a8793;text-transform:uppercase;letter-spacing:0.06em;font-weight:500">Topic</div>
      <div style="margin-top:3px;font-size:12px;font-weight:400;color:#5e3a54">{_esc(topic)}</div>
      {note_block}
    </td></tr>
  </table>
  <p style="margin:16px 0 0;font-size:12px;line-height:1.55;font-weight:400;color:#5e3a54">
    Need to reschedule? Just reply to this email — a human reads it.
  </p>
  <p style="margin:14px 0 0">
    <a href="{_esc(app)}" style="display:inline-block;background:#4b2440;color:#faf6ed;padding:10px 18px;border-radius:999px;text-decoration:none;font-size:13px;font-weight:500">
      Explore Watchfront →
    </a>
  </p>
  <p style="margin:20px 0 0;font-size:12px;font-weight:400;color:#1c0f18">
    Looking forward to it,<br/>
    <span style="color:#5e3a54">The Watchfront team</span>
  </p>
</div>
"""
    return _email_shell(
        accent="#9b1b67",
        body_html=inner,
        preheader=f"Call confirmed for {slot} — see you then.",
    )



def _post(url: str, payload: dict) -> tuple[str, str | None]:
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code >= 400:
            return "failed", f"HTTP {r.status_code}"
        return "sent", None
    except requests.RequestException as e:
        return "failed", str(e)


def dispatch(
    ws: dict,
    event: str,
    subject: str,
    body: str,
    *,
    severity: str = "major",
    incident_id=None,
    link: str | None = None,
    extra_emails: list[str] | None = None,
    kind: str | None = None,
    site: str | None = None,
    force: bool = False,
) -> None:
    s = settings_for(ws)
    if not force:
        if not s["events"].get(event, True) and event not in ("escalation", "assignment"):
            return
        if event in ("incident_opened", "incident_reopened") and SEVERITY_RANK.get(severity, 2) < SEVERITY_RANK.get(s["min_severity"], 1):
            return
        # Quiet hours mute non-critical, non-escalation noise so agencies/startups can sleep.
        if event not in ("escalation", "assignment") and severity != "critical" and _in_quiet_hours(s):
            _record(ws["_id"], "quiet_hours", "suppressed", subject, "skipped", "quiet hours", incident_id, event)
            return

    kind = kind or ("visual_change" if event == "visual_change" else "escalation" if event == "escalation" else None)
    full_body = (
        f"NEEDS ATTENTION · {(severity or 'major').upper()}\n"
        f"{subject}\n\n"
        f"{body}\n"
    )
    if site:
        full_body += f"\nWebsite: {site}"
    if kind:
        full_body += f"\nType: {KIND_LABELS.get(kind, kind)}"
    if link:
        full_body += f"\n\nOpen in Watchfront: {link}"

    html = attention_html(
        title=subject, body=body, severity=severity, event=event, kind=kind, site=site, link=link,
    )
    subj = alert_subject(subject, severity=severity, kind=kind)

    emails = extra_emails if extra_emails is not None else s["emails"]
    if not emails:
        owner_emails = [m["email"] for m in get_db().members.find({"workspace_id": ws["_id"], "role": "owner", "status": "active"})]
        emails = owner_emails
    status, err = send_email(
        emails,
        subj,
        full_body,
        html=html,
        severity=severity,
        headers={"X-Watchfront-Event": event, "X-Watchfront-Kind": kind or event},
    )
    _record(ws["_id"], "email", ", ".join(emails), subj, status, err, incident_id, event)

    text = f"*{subject}*\n{body}" + (f"\n<{link}|Open in Watchfront>" if link else "")
    if s.get("slack_webhook") and feature(ws, "slack"):
        status, err = _post(s["slack_webhook"], _slack_blocks(subject, body, severity=severity, event=event, link=link))
        _record(ws["_id"], "slack", "slack webhook", subject, status, err, incident_id, event)
    if s.get("teams_webhook") and feature(ws, "slack"):
        status, err = _post(s["teams_webhook"], {"text": text})
        _record(ws["_id"], "teams", "teams webhook", subject, status, err, incident_id, event)
    if s.get("webhook_url"):
        status, err = _post(s["webhook_url"], {"event": event, "subject": subject, "body": body,
                                               "severity": severity, "kind": kind, "site": site,
                                               "incident_id": str(incident_id) if incident_id else None,
                                               "link": link, "at": now().isoformat()})
        _record(ws["_id"], "webhook", s["webhook_url"], subject, status, err, incident_id, event)

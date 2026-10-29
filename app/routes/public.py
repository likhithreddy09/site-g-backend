"""Public (unauthenticated) endpoints — book a call, etc."""
from __future__ import annotations

import html
import logging
import re

from flask import Blueprint, jsonify

from ..config import Config
from ..db import get_db
from ..services import notify
from ..utils import ApiError, now, valid_email
from . import body

bp = Blueprint("public", __name__, url_prefix="/api/public")
log = logging.getLogger("watchfront.public")

SLOT_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2} IST$")


@bp.post("/book-call")
def book_call():
    data = body()
    name = (data.get("name") or "").strip()[:80]
    email = (data.get("email") or "").strip().lower()
    slot = (data.get("slot") or "").strip()
    note = (data.get("note") or "").strip()[:500]
    topic = (data.get("topic") or "General").strip()[:80]

    if len(name) < 2:
        raise ApiError("Please enter your name", 422, "invalid_name")
    if not valid_email(email):
        raise ApiError("Enter a valid email address", 422, "invalid_email")
    if not SLOT_RE.match(slot):
        raise ApiError("Pick a valid time slot", 422, "invalid_slot")

    doc = {
        "name": name,
        "email": email,
        "slot": slot,
        "topic": topic,
        "note": note,
        "status": "requested",
        "created_at": now(),
    }
    get_db().call_bookings.insert_one(doc)

    team = Config.SMTP_USER or "likhith.reddy@watchfront.in"
    name_h, topic_h, slot_h, note_h = html.escape(name), html.escape(topic), html.escape(slot), html.escape(note)
    # Confirmation to the visitor
    visitor_subject = "Watchfront call confirmed"
    visitor_body = (
        f"Hi {name},\n\n"
        f"Thanks for booking a call with Watchfront.\n\n"
        f"Topic: {topic}\n"
        f"When: {slot}\n"
        f"{('Note: ' + note + chr(10)) if note else ''}\n"
        "We'll join at the scheduled time. If you need to reschedule, just reply to this email.\n\n"
        "Looking forward to speaking with you,\n"
        "The Watchfront team\n"
        f"{Config.APP_URL}\n"
    )
    visitor_html = f"""\
<div style="font-family:Georgia,serif;max-width:560px;margin:0 auto;color:#1c0f18;line-height:1.55">
  <p>Hi {name_h},</p>
  <p>Thanks for booking a call with <strong>Watchfront</strong>.</p>
  <p><strong>Topic:</strong> {topic_h}<br/>
  <strong>When:</strong> {slot_h}</p>
  {f'<p><strong>Note:</strong> {note_h}</p>' if note else ''}
  <p>We'll join at the scheduled time. If you need to reschedule, just reply to this email.</p>
  <p style="color:#5e3a54">Looking forward to speaking with you,<br/>The Watchfront team</p>
</div>
"""
    st1, err1 = notify.send_email([email], visitor_subject, visitor_body, html=visitor_html)

    # Notify the team
    team_subject = f"New call booking — {name} ({slot})"
    team_body = (
        f"New Watchfront call booking\n\n"
        f"Name: {name}\nEmail: {email}\nTopic: {topic}\nWhen: {slot}\n"
        f"Note: {note or '—'}\n"
    )
    st2, err2 = notify.send_email([team], team_subject, team_body)

    log.info("book_call name=%s email=%s slot=%s visitor=%s team=%s", name, email, slot, st1, st2)
    if st1 not in ("sent", "logged"):
        raise ApiError(
            f"We saved your booking but could not send confirmation email ({err1 or st1}). We'll still reach out.",
            502,
            "booking_email_failed",
        )

    return jsonify({
        "ok": True,
        "slot": slot,
        "email_status": st1,
        "team_notified": st2 in ("sent", "logged"),
        "message": f"Appointment confirmed for {slot}. A confirmation email was sent to {email}.",
    }), 201

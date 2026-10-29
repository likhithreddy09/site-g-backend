import json
from datetime import timedelta

import requests

from ..config import Config
from ..db import get_db
from ..plans import add_usage, limits, usage
from ..security import redact
from ..utils import ApiError, now, ser

SYSTEM_PROMPT = """You are Watchfront's incident analyst for web agencies.
You receive structured monitoring evidence about one incident. Rules:
- Only state as an observation what is directly present in the evidence. Cite evidence ids (e.g. "E2").
- Anything inferred must be a hypothesis with a confidence of low, medium or high.
- Explicitly list important evidence that is missing.
- Never claim a confirmed root cause. Never suggest automatically changing production.
Respond with JSON: {"headline": str, "observations": [{"text": str, "evidence": [str]}],
"hypotheses": [{"text": str, "confidence": "low|medium|high", "evidence": [str]}],
"next_steps": [str], "missing_evidence": [str], "stakeholder_summary": str, "resolution_note_draft": str}"""


def build_evidence(inc: dict) -> list[dict]:
    db = get_db()
    ev: list[dict] = []

    def add(kind: str, at, text: str, data: dict | None = None):
        ev.append({"id": f"E{len(ev) + 1}", "kind": kind, "at": ser(at), "text": redact(text), "data": ser(data or {})})

    add("incident", inc["started_at"], f"Incident '{inc['title']}' severity={inc['severity']} status={inc['status']} "
        f"occurrences={inc.get('occurrences', 1)} reopened={inc.get('reopen_count', 0)}x. Summary: {inc.get('summary', '')}")
    window_start = inc["started_at"] - timedelta(hours=6)
    site = db.websites.find_one({"_id": inc.get("website_id")}) if inc.get("website_id") else None
    if site:
        add("website", site.get("last_check_at"), f"Website {site['name']} ({site['url']}) current status={site.get('status')}, "
            f"last HTTP={site.get('last_status_code')}, last response={site.get('last_response_ms')} ms, last error={site.get('last_error')}")
        for r in db.check_results.find({"website_id": site["_id"], "kind": "http", "at": {"$gte": window_start}}).sort("at", -1).limit(6):
            add("http_check", r["at"], f"HTTP check {r['classification']}: status={r.get('status_code')} time={r.get('response_ms')}ms error={r.get('error')}")
        if site.get("ssl"):
            s = site["ssl"]
            add("ssl", s.get("checked_at"), f"TLS status={s.get('status')} days_left={s.get('days_left')} issuer={s.get('issuer')} error={s.get('error')}")
        for g in db.error_groups.find({"website_id": site["_id"], "last_seen": {"$gte": window_start}}).sort("count", -1).limit(5):
            add("browser_error" if g["kind"] == "js" else "rum_api_error", g["last_seen"],
                f"{g['kind'].upper()} error group seen {g['count']}x (first {ser(g['first_seen'])}): {g['message'][:300]}",
                {"release": g.get("last_release"), "pages": list((g.get("pages") or {}).keys())[:5]})
        for t in db.browser_tests.find({"website_id": site["_id"]}).limit(5):
            run = db.test_runs.find_one({"test_id": t["_id"]}, sort=[("at", -1)])
            if run:
                add("browser_test", run["at"], f"Journey '{t['name']}' last run ok={run['ok']} error={run.get('error')}",
                    {"console": [c["text"] for c in (run.get("console") or [])][:5],
                     "network_failures": (run.get("network_failures") or [])[:5]})
        for c in db.check_results.find({"website_id": site["_id"], "kind": "api", "at": {"$gte": window_start}, "ok": False}).sort("at", -1).limit(3):
            add("api_check", c["at"], f"API check failed: status={c.get('status_code')} error={c.get('error')}")
    for e in (inc.get("evidence") or [])[-5:]:
        if e.get("type") == "test_run" and e.get("ref_id"):
            run = db.test_runs.find_one({"_id": e["ref_id"]})
            if run:
                failed = [s for s in run.get("steps", []) if s.get("ok") is False]
                add("test_run", run["at"], f"Journey run failed at step: {failed[0] if failed else 'n/a'}",
                    {"console": [c["text"] for c in (run.get("console") or [])][:8], "network_failures": (run.get("network_failures") or [])[:8]})
        elif e.get("summary"):
            add(e.get("type", "evidence"), e.get("at"), str(e.get("summary")))
    for n in (inc.get("notes") or [])[-3:]:
        add("team_note", n.get("at"), f"Team note: {n.get('text', '')[:300]}")
    return ev


def _heuristic(inc: dict, ev: list[dict]) -> dict:
    kinds = {e["kind"] for e in ev}
    texts = " ".join(e["text"].lower() for e in ev)
    obs = [{"text": e["text"], "evidence": [e["id"]]} for e in ev if e["kind"] != "incident"][:8]
    hyps, steps, missing = [], [], []

    def ref(kind):
        return [e["id"] for e in ev if e["kind"] == kind][:3]

    st = inc["source_type"]
    if st == "website":
        if "timed out" in texts or "timeout" in texts:
            hyps.append({"text": "The origin server or upstream (database, PHP workers) is overloaded or not responding within the timeout.", "confidence": "medium", "evidence": ref("http_check")})
            steps += ["Check hosting control panel for CPU/memory saturation and PHP worker limits.", "Review server error logs around the first failure time."]
        if "dns" in texts:
            hyps.append({"text": "DNS records changed or the DNS provider is failing to resolve the domain.", "confidence": "medium", "evidence": ref("http_check")})
            steps.append("Verify A/CNAME records with `dig` from multiple resolvers and check recent DNS changes.")
        if "http 5" in texts or "status=50" in texts:
            hyps.append({"text": "The application is throwing server errors (5xx), commonly after a plugin/theme/code update or a failed dependency.", "confidence": "medium", "evidence": ref("http_check")})
            steps += ["Inspect application error logs (e.g. wp-content/debug.log) for fatal errors.", "Roll back the most recent deployment or plugin update if timing matches."]
        if "http 4" in texts or "status=40" in texts:
            hyps.append({"text": "The URL now returns a client error; the page may have moved, been unpublished, or blocked by a firewall/WAF.", "confidence": "low", "evidence": ref("http_check")})
            steps.append("Open the URL in a browser and check firewall/WAF or security plugin logs for blocked bot traffic.")
        if "content" in texts or "expected text" in texts:
            hyps.append({"text": "The page loads but its content changed — possibly a maintenance page, error template, or edited content.", "confidence": "medium", "evidence": ref("http_check")})
    elif st == "browser_test":
        hyps.append({"text": "A change to the page structure, script, or backend integration is preventing the journey from completing.", "confidence": "medium", "evidence": ref("test_run") + ref("browser_test")})
        if "browser_error" in kinds or "exception" in texts:
            hyps.append({"text": "A JavaScript exception recorded during the run may be stopping the form/button handler.", "confidence": "medium", "evidence": ref("browser_error") + ref("test_run")})
        if "status" in texts and ("500" in texts or "502" in texts or "503" in texts):
            hyps.append({"text": "A backend request made during the journey returned a server error.", "confidence": "medium", "evidence": ref("test_run")})
        steps += ["Open the failure screenshot and compare it with the last passing run.", "Reproduce the journey manually with DevTools open (Console + Network).",
                  "Check whether selectors used in the failing step still exist after the latest deployment."]
    elif st == "api":
        hyps.append({"text": "The API endpoint or an upstream dependency is failing, or the response contract changed.", "confidence": "medium", "evidence": ref("api_check")})
        steps += ["Call the endpoint manually with the same headers and compare the response.", "Check API provider status pages and recent credential rotations."]
    elif st == "ssl":
        hyps.append({"text": "Certificate auto-renewal (e.g. Let's Encrypt/hosting AutoSSL) failed or the wrong certificate is being served.", "confidence": "medium", "evidence": ref("ssl")})
        steps += ["Check the certificate renewal job / hosting SSL panel.", "Confirm DNS points at the server issuing the certificate."]
    elif st == "domain":
        hyps.append({"text": "The domain registration is approaching expiry and auto-renew may be off or the payment method invalid.", "confidence": "medium", "evidence": []})
        steps.append("Log in to the registrar, verify auto-renew and billing details.")
    elif st in ("js_errors", "rum_api"):
        hyps.append({"text": "A recent frontend release or third-party script introduced errors for real visitors.", "confidence": "medium", "evidence": ref("browser_error") + ref("rum_api_error")})
        steps += ["Check the release identifier on the error group and compare with deployment times.", "Use the stack trace to locate the failing handler."]
    elif st == "page_check":
        hyps.append({"text": "A content edit or deployment removed expected elements or text from the page.", "confidence": "medium", "evidence": []})
        steps.append("Compare the latest screenshot with the approved baseline and check the CMS revision history.")
    if not hyps:
        hyps.append({"text": "Not enough correlated evidence to suggest a specific cause.", "confidence": "low", "evidence": []})
    if "browser_error" not in kinds:
        missing.append("No browser JavaScript errors recorded — install the Watchfront script to capture frontend errors.")
    if "browser_test" not in kinds and st != "browser_test":
        missing.append("No user-journey test covers this website.")
    missing.append("No deployment records are linked; deployment timing cannot be correlated.")
    status_txt = "has recovered" if inc["status"] == "resolved" else "is ongoing"
    return {
        "headline": f"{inc['title']} — {status_txt}",
        "observations": obs, "hypotheses": hyps[:4], "next_steps": steps[:6] or ["Review the attached evidence."],
        "missing_evidence": missing,
        "stakeholder_summary": f"We detected an issue: {inc['title'].lower()}. It was first detected at {ser(inc['started_at'])[:16].replace('T', ' ')} UTC "
                               f"and {status_txt}. Our team {'resolved it and continues to monitor' if inc['status'] == 'resolved' else 'is investigating'}.",
        "resolution_note_draft": f"Issue: {inc['title']}.\nDetected: {ser(inc['started_at'])[:16]} UTC.\nCause: [confirm cause].\n"
                                 f"Fix applied: [describe fix].\nVerification: Watchfront monitoring confirmed recovery.",
    }


def _llm(ev: list[dict]) -> dict:
    r = requests.post(f"{Config.OPENAI_BASE_URL}/chat/completions", timeout=60,
                      headers={"Authorization": f"Bearer {Config.OPENAI_API_KEY}"},
                      json={"model": Config.OPENAI_MODEL, "temperature": 0.2, "response_format": {"type": "json_object"},
                            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                                         {"role": "user", "content": json.dumps({"evidence": ev})[:60000]}]})
    r.raise_for_status()
    return json.loads(r.json()["choices"][0]["message"]["content"])


def diagnose(ws: dict, inc: dict) -> dict:
    cap = limits(ws).get("ai_calls", 0)
    if cap <= 0:
        raise ApiError("AI diagnosis is not included in your plan", 402, "plan_limit")
    if usage(ws)["ai_calls"] >= cap:
        raise ApiError(f"Monthly AI limit reached ({cap} analyses).", 429, "quota")
    if (ws.get("settings") or {}).get("ai_enabled") is False:
        raise ApiError("AI analysis is disabled in workspace settings", 403, "disabled")
    ev = build_evidence(inc)
    engine = "heuristic"
    if Config.OPENAI_API_KEY:
        try:
            out = _llm(ev)
            engine = Config.OPENAI_MODEL
        except Exception as e:  # noqa: BLE001
            out = _heuristic(inc, ev)
            out["engine_note"] = f"LLM unavailable ({str(e)[:80]}); used rule-based analysis."
    else:
        out = _heuristic(inc, ev)
    add_usage(ws["_id"], "ai_calls", 1)
    result = {**out, "engine": engine, "evidence": ev, "generated_at": now(),
              "disclaimer": "AI-assisted suggestions based on captured evidence. Hypotheses are not confirmed root causes."}
    get_db().incidents.update_one({"_id": inc["_id"]}, {"$set": {"ai": result}})
    return result

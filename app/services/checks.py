import json
import socket
import ssl
import time
from datetime import timedelta, timezone
from urllib.parse import urljoin, urlparse

import requests
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from ..db import get_db
from ..security import check_host_allowed, decrypt, redact, validate_target
from ..utils import now, parse_dt
from . import incidents

USER_AGENT = "WatchfrontBot/1.0 (+https://watchfront.in/bot; uptime monitoring)"
MAX_BODY = 2_000_000


class TargetBlocked(Exception):
    pass


class HttpOutcome:
    def __init__(self, status, headers, body: bytes, elapsed_ms, hops, final_url):
        self.status = status
        self.headers = headers
        self.body = body
        self.elapsed_ms = elapsed_ms
        self.hops = hops
        self.final_url = final_url

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def http_request(url, method="GET", headers=None, params=None, data=None, json_body=None,
                 timeout=10, max_redirects=5) -> HttpOutcome:
    """HTTP request that re-validates every redirect hop against SSRF rules."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})}
    cur, m, hops, total = url, method.upper(), [], 0.0
    with requests.Session() as session:
        for i in range(max_redirects + 1):
            ok, reason = validate_target(cur)
            if not ok:
                raise TargetBlocked(reason)
            t0 = time.perf_counter()
            resp = session.request(m, cur, headers=hdrs, params=params if i == 0 else None,
                                   data=data if i == 0 else None, json=json_body if i == 0 else None,
                                   timeout=timeout, allow_redirects=False, stream=True)
            body = b""
            if m != "HEAD":
                for chunk in resp.iter_content(65536):
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
            resp.close()
            total += (time.perf_counter() - t0) * 1000
            if resp.is_redirect and resp.headers.get("Location") and i < max_redirects:
                nxt = urljoin(cur, resp.headers["Location"])
                hops.append({"url": cur, "status": resp.status_code, "location": nxt})
                if resp.status_code in (301, 302, 303) and m not in ("GET", "HEAD"):
                    m = "GET"
                cur = nxt
                continue
            return HttpOutcome(resp.status_code, dict(resp.headers), body, round(total, 1), hops, cur)
    raise requests.TooManyRedirects("Too many redirects")


def classify_exception(e: Exception) -> tuple[str, str]:
    if isinstance(e, TargetBlocked):
        return "blocked", str(e)
    if isinstance(e, requests.Timeout):
        return "timeout", "Request timed out"
    if isinstance(e, requests.exceptions.SSLError):
        return "ssl", f"TLS error: {str(e)[:200]}"
    if isinstance(e, requests.ConnectionError):
        msg = str(e)
        if "Name or service not known" in msg or "nodename nor servname" in msg or "getaddrinfo" in msg:
            return "dns", "DNS resolution failed"
        if "refused" in msg.lower():
            return "connection", "Connection refused"
        return "connection", f"Connection error: {msg[:200]}"
    if isinstance(e, requests.TooManyRedirects):
        return "redirect", "Too many redirects"
    return "error", str(e)[:300]


# ------------------------------------------------------------------ website uptime


def _website_attempt(site: dict) -> dict:
    expected = site.get("expected_statuses") or [200, 201, 202, 203, 204, 301, 302]
    try:
        out = http_request(site["url"], timeout=site.get("timeout_sec", 10))
    except Exception as e:  # noqa: BLE001
        cat, msg = classify_exception(e)
        return {"ok": False, "error_type": cat, "error": msg, "status_code": None, "response_ms": None}
    res = {"ok": True, "status_code": out.status, "response_ms": out.elapsed_ms, "final_url": out.final_url,
           "redirects": out.hops, "bytes": len(out.body), "error_type": None, "error": None}
    if out.status not in expected:
        res.update(ok=False, error_type="status", error=f"Unexpected HTTP {out.status} (expected {', '.join(map(str, expected))})")
        return res
    text = out.text.lower()
    missing = [k for k in site.get("keyword_present") or [] if k and k.lower() not in text]
    forbidden = [k for k in site.get("keyword_absent") or [] if k and k.lower() in text]
    if missing:
        res.update(ok=False, error_type="content", error=f"Expected text missing: {', '.join(missing)}")
    elif forbidden:
        res.update(ok=False, error_type="content", error=f"Error text found on page: {', '.join(forbidden)}")
    elif len(out.body) == 0 and out.status == 200:
        res.update(ok=False, error_type="content", error="Empty response body")
    return res


def run_website_check(site_id) -> None:
    db = get_db()
    site = db.websites.find_one({"_id": site_id})
    if not site or site.get("paused"):
        return
    ws = db.workspaces.find_one({"_id": site["workspace_id"]})
    attempts = []
    retries = int(site.get("retries", 2))
    for attempt in range(retries + 1):
        r = _website_attempt(site)
        r["attempt"] = attempt + 1
        attempts.append(r)
        if r["ok"] or r.get("error_type") == "blocked":
            break
        if attempt < retries:
            time.sleep(min(30, int(site.get("retry_delay_sec", 5))))
    final = attempts[-1]
    classification = "ok" if final["ok"] and len(attempts) == 1 else ("transient" if final["ok"] else "failure")
    t = now()
    result = {
        "workspace_id": site["workspace_id"], "website_id": site["_id"], "kind": "http", "at": t,
        "ok": final["ok"], "classification": classification, "status_code": final.get("status_code"),
        "response_ms": final.get("response_ms"), "error_type": final.get("error_type"), "error": final.get("error"),
        "attempts": [{k: a.get(k) for k in ("attempt", "ok", "status_code", "response_ms", "error")} for a in attempts],
        "details": {"final_url": final.get("final_url"), "redirects": final.get("redirects"), "bytes": final.get("bytes")},
    }
    result["_id"] = db.check_results.insert_one(result).inserted_id

    upd = {"last_check_at": t, "last_status_code": final.get("status_code"), "last_response_ms": final.get("response_ms"),
           "last_error": final.get("error"), "last_result_id": result["_id"]}
    key = f"down:{site['_id']}"
    threshold = int(site.get("failure_threshold", 2))
    if final["ok"]:
        slow = site.get("slow_threshold_ms") and final["response_ms"] and final["response_ms"] > site["slow_threshold_ms"]
        upd.update(status="degraded" if slow else "up", consecutive_failures=0)
        db.websites.update_one({"_id": site["_id"]}, {"$set": upd})
        incidents.auto_resolve(ws, key, f"{site['name']} is responding again (HTTP {final.get('status_code')}).")
    else:
        fails = int(site.get("consecutive_failures", 0)) + 1
        confirmed = fails >= threshold
        upd.update(consecutive_failures=fails, status="down" if confirmed else "degraded")
        db.websites.update_one({"_id": site["_id"]}, {"$set": upd})
        if confirmed:
            sev = "critical" if final["error_type"] in ("timeout", "dns", "connection", "ssl") or (final.get("status_code") or 0) >= 500 else "major"
            incidents.open_or_update(
                ws, key=key, source_type="website", source_id=site["_id"], website_id=site["_id"], client_id=site.get("client_id"),
                title=f"{site['name']} is down" if final["error_type"] != "content" else f"{site['name']} content check failing",
                severity=sev, summary=f"{final['error']} — confirmed after {fails} consecutive failed checks ({len(attempts)} attempts in latest check).",
                evidence={"type": "check_result", "ref_id": result["_id"], "summary": final["error"], "status_code": final.get("status_code")},
            )


# ------------------------------------------------------------------ SSL


def fetch_certificate(host: str, port: int = 443, timeout: int = 10) -> dict:
    ok, reason = check_host_allowed(host)
    if not ok:
        raise TargetBlocked(reason)
    info: dict = {"host": host, "checked_at": now()}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            der = s.getpeercert(binary_form=True)
            info["protocol"] = s.version()
    cert = x509.load_der_x509_certificate(der)
    nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

    def _cn(name):
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else name.rfc4514_string()

    def _issuer(name):
        orgs = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if orgs and orgs[0].value and str(orgs[0].value).lower() not in {"none", "null"}:
            return str(orgs[0].value)
        return _cn(name)

    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    info.update(subject=_cn(cert.subject), issuer=_issuer(cert.issuer), valid_from=nb, valid_to=na, sans=sans[:20],
                days_left=(na - now()).days, serial=format(cert.serial_number, "x"))

    vctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                pass
        info.update(valid=True, error=None)
    except ssl.SSLCertVerificationError as e:
        info.update(valid=False, error=getattr(e, "verify_message", None) or str(e))
    except ssl.SSLError as e:
        info.update(valid=False, error=str(e))
    return info


def run_ssl_check(site_id) -> None:
    db = get_db()
    site = db.websites.find_one({"_id": site_id})
    if not site:
        return
    ws = db.workspaces.find_one({"_id": site["workspace_id"]})
    host = urlparse(site["url"]).hostname
    t = now()
    try:
        info = fetch_certificate(host)
        # HTTPS redirect validation
        try:
            out = http_request(f"http://{host}/", timeout=8)
            info["http_redirects_to_https"] = out.final_url.startswith("https://")
        except Exception:  # noqa: BLE001
            info["http_redirects_to_https"] = None
    except Exception as e:  # noqa: BLE001
        info = {"host": host, "checked_at": t, "valid": False, "error": f"Could not establish TLS connection: {str(e)[:200]}",
                "days_left": None, "unreachable": True}
    status = "valid" if info.get("valid") else "invalid"
    windows = sorted(site.get("ssl_reminder_days") or [30, 14, 7, 1], reverse=True)
    if info.get("valid") and info.get("days_left") is not None and info["days_left"] <= windows[0]:
        status = "expiring"
    info["status"] = status
    res = {"workspace_id": site["workspace_id"], "website_id": site["_id"], "kind": "ssl", "at": t,
           "ok": status == "valid", "classification": "ok" if status != "invalid" else "failure",
           "error": info.get("error"), "details": info}
    rid = db.check_results.insert_one(res).inserted_id
    db.websites.update_one({"_id": site["_id"]}, {"$set": {"ssl": info, "ssl_next_at": t + timedelta(hours=6)}})

    if not site.get("url", "").startswith("https://") and info.get("unreachable"):
        return
    inv_key, exp_key = f"ssl_invalid:{site['_id']}", f"ssl_expiry:{site['_id']}"
    if status == "invalid":
        incidents.open_or_update(ws, key=inv_key, source_type="ssl", source_id=site["_id"], website_id=site["_id"],
                                 client_id=site.get("client_id"), severity="critical",
                                 title=f"SSL certificate problem on {host}", summary=info.get("error") or "Certificate invalid",
                                 evidence={"type": "ssl", "ref_id": rid, "summary": info.get("error")})
    else:
        incidents.auto_resolve(ws, inv_key, "Certificate validates correctly again.")
    if status == "expiring":
        d = info["days_left"]
        sev = "critical" if d <= 3 else "major" if d <= 7 else "minor"
        incidents.open_or_update(ws, key=exp_key, source_type="ssl", source_id=site["_id"], website_id=site["_id"],
                                 client_id=site.get("client_id"), severity=sev,
                                 title=f"SSL certificate for {host} expires in {d} days",
                                 summary=f"Certificate issued by {info.get('issuer')} expires on {info['valid_to'].date()}.",
                                 evidence={"type": "ssl", "ref_id": rid, "summary": f"{d} days left"})
    elif status == "valid":
        incidents.auto_resolve(ws, exp_key, "Certificate renewed.")


# ------------------------------------------------------------------ domain expiry (RDAP)

_TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "org.in",
              "firm.in", "gen.in", "ind.in", "co.nz", "com.br", "co.jp", "com.sg", "com.mx", "co.za", "com.cn", "gc.ca"}


def registrable_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def run_domain_check(site_id) -> None:
    db = get_db()
    site = db.websites.find_one({"_id": site_id})
    if not site:
        return
    ws = db.workspaces.find_one({"_id": site["workspace_id"]})
    domain = registrable_domain(urlparse(site["url"]).hostname or "")
    info = {"domain": domain, "checked_at": now(), "status": "unknown", "expires_at": None, "registrar": None, "days_left": None}
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=15, headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
        if r.status_code == 200:
            data = r.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") == "expiration":
                    info["expires_at"] = parse_dt(ev["eventDate"])
                if ev.get("eventAction") == "registration":
                    info["registered_at"] = parse_dt(ev["eventDate"])
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    vcard = (ent.get("vcardArray") or [None, []])[1]
                    for item in vcard:
                        if item[0] == "fn":
                            info["registrar"] = item[3]
            if info["expires_at"]:
                info["days_left"] = (info["expires_at"] - now()).days
                windows = sorted(site.get("domain_reminder_days") or [60, 30, 14, 7], reverse=True)
                info["status"] = "expiring" if info["days_left"] <= windows[0] else "valid"
            else:
                info["note"] = "Registry did not publish an expiration date."
        else:
            info["note"] = f"Registration data unavailable (RDAP HTTP {r.status_code})."
    except (requests.RequestException, ValueError) as e:
        info["note"] = f"Registration data unavailable: {str(e)[:120]}"
    db.check_results.insert_one({"workspace_id": site["workspace_id"], "website_id": site["_id"], "kind": "domain",
                                 "at": now(), "ok": info["status"] != "expiring", "classification": "ok",
                                 "error": info.get("note"), "details": info})
    db.websites.update_one({"_id": site["_id"]}, {"$set": {"domain": info, "domain_next_at": now() + timedelta(hours=24)}})
    key = f"domain_expiry:{site['_id']}"
    if info["status"] == "expiring":
        d = info["days_left"]
        incidents.open_or_update(ws, key=key, source_type="domain", source_id=site["_id"], website_id=site["_id"],
                                 client_id=site.get("client_id"), severity="critical" if d <= 7 else "major",
                                 title=f"Domain {domain} expires in {d} days",
                                 summary=f"Registrar: {info.get('registrar') or 'unknown'}. Renew before {info['expires_at'].date()}.",
                                 evidence={"type": "domain", "summary": f"{d} days left"})
    elif info["status"] == "valid":
        incidents.auto_resolve(ws, key, "Domain registration renewed.")


# ------------------------------------------------------------------ API monitors


def _json_path(data, path: str):
    cur = data
    for part in [p for p in path.replace("[", ".").replace("]", "").split(".") if p]:
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur


def evaluate_assertion(a: dict, status: int, headers: dict, text: str, elapsed: float) -> dict:
    kind, op, expected = a.get("type"), a.get("op", "equals"), a.get("value")
    out = {**a, "ok": False, "actual": None}
    try:
        if kind == "body_contains":
            out["ok"] = str(expected) in text
            out["actual"] = "present" if out["ok"] else "absent"
            return out
        if kind == "body_not_contains":
            out["ok"] = str(expected) not in text
            return out
        if kind == "header":
            actual = {k.lower(): v for k, v in headers.items()}.get(str(a.get("path", "")).lower())
        elif kind == "json_path":
            actual = _json_path(json.loads(text), a.get("path", ""))
        elif kind == "response_time":
            actual = elapsed
        else:
            out["error"] = "Unknown assertion type"
            return out
        out["actual"] = actual if not isinstance(actual, (dict, list)) else json.dumps(actual)[:200]
        if op == "exists":
            out["ok"] = actual is not None
        elif op == "equals":
            out["ok"] = str(actual).lower() == str(expected).lower()
        elif op == "not_equals":
            out["ok"] = str(actual).lower() != str(expected).lower()
        elif op == "contains":
            out["ok"] = str(expected).lower() in str(actual).lower()
        elif op in ("gt", "lt"):
            a_num, e_num = float(actual), float(expected)
            out["ok"] = a_num > e_num if op == "gt" else a_num < e_num
    except (KeyError, IndexError, ValueError, TypeError) as e:
        out["error"] = f"Could not evaluate: {e}"
    return out


def _api_attempt(mon: dict) -> dict:
    headers = dict(mon.get("headers") or {})
    for k, v in (mon.get("secret_headers_enc") or {}).items():
        headers[k] = decrypt(v)
    body = mon.get("body") or None
    data = json_body = None
    if body and mon.get("method", "GET") not in ("GET", "HEAD"):
        if mon.get("body_type", "json") == "json":
            try:
                json_body = json.loads(body)
            except ValueError:
                return {"ok": False, "error_type": "config", "error": "Request body is not valid JSON"}
        else:
            data = body
    try:
        out = http_request(mon["url"], method=mon.get("method", "GET"), headers=headers, params=mon.get("query") or None,
                           data=data, json_body=json_body, timeout=mon.get("timeout_sec", 15), max_redirects=3)
    except Exception as e:  # noqa: BLE001
        cat, msg = classify_exception(e)
        return {"ok": False, "error_type": cat, "error": msg, "status_code": None, "response_ms": None}
    expected = mon.get("expected_statuses") or [200]
    res = {"ok": True, "status_code": out.status, "response_ms": out.elapsed_ms, "error_type": None, "error": None,
           "bytes": len(out.body)}
    text = out.text
    assertions = [evaluate_assertion(a, out.status, out.headers, text, out.elapsed_ms) for a in mon.get("assertions") or []]
    res["assertions"] = assertions
    if mon.get("store_body"):
        res["body_sample"] = redact(text[:2000])
    if out.status not in expected:
        res.update(ok=False, error_type="status", error=f"HTTP {out.status} (expected {', '.join(map(str, expected))})")
    elif mon.get("max_response_ms") and out.elapsed_ms > mon["max_response_ms"]:
        res.update(ok=False, error_type="slow", error=f"Response took {out.elapsed_ms:.0f} ms (limit {mon['max_response_ms']} ms)")
    elif any(not a["ok"] for a in assertions):
        failed = [a for a in assertions if not a["ok"]]
        res.update(ok=False, error_type="assertion",
                   error="Assertion failed: " + "; ".join(f"{a['type']} {a.get('path', '')} {a.get('op', '')} {a.get('value', '')} (got {a.get('actual')})".strip() for a in failed[:3]))
    return res


def run_api_check(mon_id) -> dict | None:
    db = get_db()
    mon = db.api_monitors.find_one({"_id": mon_id})
    if not mon:
        return None
    ws = db.workspaces.find_one({"_id": mon["workspace_id"]})
    attempts = []
    retries = int(mon.get("retries", 1))
    for attempt in range(retries + 1):
        r = _api_attempt(mon)
        r["attempt"] = attempt + 1
        attempts.append(r)
        if r["ok"] or r.get("error_type") in ("blocked", "config"):
            break
        if attempt < retries:
            time.sleep(3)
    final = attempts[-1]
    t = now()
    classification = "ok" if final["ok"] and len(attempts) == 1 else ("transient" if final["ok"] else "failure")
    result = {"workspace_id": mon["workspace_id"], "monitor_id": mon["_id"], "website_id": mon.get("website_id"),
              "kind": "api", "at": t, "ok": final["ok"], "classification": classification,
              "status_code": final.get("status_code"), "response_ms": final.get("response_ms"),
              "error_type": final.get("error_type"), "error": final.get("error"),
              "details": {"assertions": final.get("assertions", []), "body_sample": final.get("body_sample"),
                          "attempts": len(attempts), "source": "scheduled"}}
    result["_id"] = db.check_results.insert_one(result).inserted_id
    key = f"api:{mon['_id']}"
    if final["ok"]:
        db.api_monitors.update_one({"_id": mon["_id"]}, {"$set": {"status": "up", "consecutive_failures": 0, "last_check_at": t,
                                                                   "last_response_ms": final.get("response_ms"), "last_status_code": final.get("status_code"), "last_error": None}})
        incidents.auto_resolve(ws, key, f"API check '{mon['name']}' is passing again.")
    else:
        fails = int(mon.get("consecutive_failures", 0)) + 1
        confirmed = fails >= int(mon.get("failure_threshold", 2))
        db.api_monitors.update_one({"_id": mon["_id"]}, {"$set": {"status": "down" if confirmed else "degraded", "consecutive_failures": fails,
                                                                   "last_check_at": t, "last_response_ms": final.get("response_ms"),
                                                                   "last_status_code": final.get("status_code"), "last_error": final.get("error")}})
        if confirmed:
            site = db.websites.find_one({"_id": mon.get("website_id")}) if mon.get("website_id") else None
            incidents.open_or_update(ws, key=key, source_type="api", source_id=mon["_id"], website_id=mon.get("website_id"),
                                     client_id=(site or {}).get("client_id") or mon.get("client_id"),
                                     severity="critical" if final.get("error_type") in ("timeout", "connection", "dns") or (final.get("status_code") or 0) >= 500 else "major",
                                     title=f"API check failing: {mon['name']}", summary=final.get("error") or "",
                                     evidence={"type": "check_result", "ref_id": result["_id"], "summary": final.get("error"), "status_code": final.get("status_code")})
    return result

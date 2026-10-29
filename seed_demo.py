"""Create a demo workspace with real monitoring data against a running API.

Usage: python seed_demo.py [email] [password]
"""
import sys
import time

import requests

API = "http://localhost:5050"
EMAIL = sys.argv[1] if len(sys.argv) > 1 else "demo@watchfront.in"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else "demo12345"

s = requests.Session()


def call(method, path, **kw):
    r = s.request(method, API + path, timeout=180, **kw)
    if r.status_code >= 400:
        print(f"  {method} {path} -> {r.status_code} {r.text[:200]}")
        return None
    return r.json() if r.content else None


r = s.post(f"{API}/api/auth/register", json={"name": "Demo User", "email": EMAIL, "password": PASSWORD, "workspace_name": "Northline Digital"})
if r.status_code == 409:
    r = s.post(f"{API}/api/auth/login", json={"email": EMAIL, "password": PASSWORD})
r.raise_for_status()
auth = r.json()
s.headers["Authorization"] = f"Bearer {auth['token']}"
ws_id = auth["workspaces"][0]["id"]
s.headers["X-Workspace-Id"] = ws_id
print("workspace", ws_id)

clients = {c["name"]: c["id"] for c in call("GET", "/api/clients") or []}
for name in ("Lotusdew Wealth", "Acme Retail"):
    if name not in clients:
        clients[name] = call("POST", "/api/clients", json={"name": name, "contact_email": "ops@example.com"})["id"]

existing = {w["url"]: w for w in call("GET", "/api/websites") or []}
sites = {}
for url, client, name in [
    ("https://www.lotusdew.in/", "Lotusdew Wealth", "Lotusdew — Home"),
    ("https://github.com/", "Acme Retail", "Acme storefront"),
    ("https://httpbin.org/status/503", "Acme Retail", "Acme checkout API"),
    ("https://example.com/", None, "Agency site"),
]:
    w = next((v for k, v in existing.items() if k.rstrip("/") == url.rstrip("/")), None)
    if not w:
        w = call("POST", "/api/websites", json={"url": url, "name": name, "client_id": clients.get(client), "interval_sec": 300,
                                                "retries": 0, "failure_threshold": 1})
    if w:
        sites[name] = w
        print("site", name, w.get("status"))

lotus = sites["Lotusdew — Home"]["id"]

if not call("GET", "/api/page-checks"):
    print("page check", (call("POST", "/api/page-checks", json={
        "name": "Lotusdew homepage", "url": "https://www.lotusdew.in/", "website_id": lotus,
        "expected_texts": ["SEBI Registered Research Analyst", "Book a Call", "View Portfolios"],
        "required_selectors": ["nav", "footer"], "visual_enabled": True, "threshold_pct": 1, "check_links": True,
        "interval_sec": 3600}) or {}).get("status"))

mons = call("GET", "/api/api-monitors") or []
if not mons:
    for name, url, query in [("Portfolios API", "https://api.lotusdew.in/products/data", {"page": "1", "source": "smallcase"}),
                             ("RMS API", "https://api.lotusdew.in/rms", {})]:
        m = call("POST", "/api/api-monitors", json={
            "name": name, "method": "GET", "url": url, "query": query, "website_id": lotus, "expected_statuses": ["200"],
            "assertions": [{"type": "json_path", "path": "encryptedData", "op": "exists", "value": ""},
                           {"type": "response_time", "op": "lt", "value": "2000"}],
            "interval_sec": 300, "max_response_ms": 3000})
        if m:
            call("POST", f"/api/api-monitors/{m['id']}/run")
            print("api monitor", name)

site_key = call("GET", f"/api/websites/{lotus}")["site_key"]
events = [
    {"type": "js", "message": "TypeError: Cannot read properties of undefined (reading 'returns')", "source": "https://www.lotusdew.in/_next/static/chunks/portfolio.js", "line": 1, "col": 4821, "stack": "TypeError: Cannot read properties of undefined (reading 'returns')\n    at PortfolioCard (portfolio.js:1:4821)"},
    {"type": "api", "message": "GET https://api.lotusdew.in/products/data → 502", "api": {"url": "https://api.lotusdew.in/products/data", "method": "GET", "status": 502, "duration_ms": 30012}},
    {"type": "js", "message": "Unhandled promise rejection: ChunkLoadError: Loading chunk 812 failed.", "source": "https://www.lotusdew.in/"},
]
uas = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"]
for i, ev in enumerate(events):
    for n in range(3 + i * 4):
        requests.post(f"{API}/ingest", json={**ev, "site_key": site_key, "release": "v2.4.1", "ua": uas[n % 2],
                                             "page_url": ["https://www.lotusdew.in/", "https://www.lotusdew.in/portfolios"][n % 2],
                                             "viewport": "1366x900", "ts": int(time.time() * 1000)}, timeout=10)
print("ingested browser events")

incs = (call("GET", "/api/incidents") or {}).get("incidents") or []
for inc in incs:
    if inc.get("source_type") == "website" and not inc.get("notes"):
        call("POST", f"/api/incidents/{inc['id']}/diagnose")
        call("POST", f"/api/incidents/{inc['id']}/notes", json={"text": "Checked with Acme's dev team — upstream payment gateway is returning 503."})
        print("diagnosed", inc["title"])

if not (call("GET", "/api/reports") or []):
    call("POST", "/api/reports", json={"days": 7, "client_id": clients["Lotusdew Wealth"]})
print("done — sign in as", EMAIL, "/", PASSWORD)

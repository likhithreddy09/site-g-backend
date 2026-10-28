"""End-to-end smoke test against a running API (python smoke_test.py)."""
import sys
import time

import requests

API = "http://localhost:5050"
s = requests.Session()


def call(method, path, expect=(200, 201), **kw):
    r = s.request(method, API + path, timeout=180, **kw)
    if r.status_code not in expect:
        print(f"FAIL {method} {path} -> {r.status_code} {r.text[:300]}")
        sys.exit(1)
    print(f"ok   {method} {path} -> {r.status_code}")
    return r.json() if r.content else None


email = f"smoke{int(time.time())}@example.com"
sess = call("POST", "/api/auth/register", json={"email": email, "password": "password123", "name": "Smoke", "workspace_name": "Smoke Agency"})
s.headers.update({"Authorization": f"Bearer {sess['token']}", "X-Workspace-Id": sess["workspaces"][0]["id"]})

call("POST", "/api/websites", expect=(422,), json={"url": "not a url"})
call("POST", "/api/websites", expect=(422,), json={"url": "http://127.0.0.1"})
client = call("POST", "/api/clients", json={"name": "Acme Dental"})
site = call("POST", "/api/websites", json={"url": "https://example.com", "client_id": client["id"], "keyword_present": ["Example Domain"]})
print("     first check:", site["status"], site.get("last_response_ms"))
call("POST", "/api/websites", expect=(409,), json={"url": "https://example.com/"})
bad = call("POST", "/api/websites", json={"url": "https://httpbin.org/status/503", "retries": 0, "failure_threshold": 1})
print("     failing site:", bad["status"], bad.get("last_error"))
call("POST", f"/api/websites/{site['id']}/check?kind=ssl")
site_d = call("GET", f"/api/websites/{site['id']}")
print("     ssl:", site_d.get("ssl", {}).get("status"), site_d.get("ssl", {}).get("days_left"))
call("GET", f"/api/websites/{site['id']}/stats?hours=24")

mon = call("POST", "/api/api-monitors", json={"name": "httpbin json", "url": "https://httpbin.org/json", "website_id": site["id"],
                                             "secret_headers": {"Authorization": "Bearer abc"},
                                             "assertions": [{"type": "json_path", "path": "slideshow.author", "op": "equals", "value": "Yours Truly"}]})
assert mon["secret_headers"]["Authorization"] == "••••••"
res = call("POST", f"/api/api-monitors/{mon['id']}/run")
print("     api check:", res["ok"], res.get("error"))

pc = call("POST", "/api/page-checks", json={"name": "Example home", "url": "https://example.com", "website_id": site["id"],
                                           "expected_texts": ["Example Domain"], "required_selectors": ["h1"], "check_links": True})
pcr = call("POST", f"/api/page-checks/{pc['id']}/run")
print("     page check:", pcr["status"], (pcr["results"][0]["details"] or {}).get("visual"))

test = call("POST", "/api/browser-tests", json={
    "name": "Login journey", "start_url": "https://the-internet.herokuapp.com/login", "website_id": site["id"],
    "steps": [{"action": "fill", "selector": "#username", "value": "tomsmith"},
              {"action": "fill", "selector": "#password", "value": "SuperSecretPassword!", "secret": True},
              {"action": "click", "selector": "button[type=submit]"},
              {"action": "assert_text", "selector": "#flash", "value": "You logged into a secure area"}]})
call("POST", f"/api/browser-tests/{test['id']}/run", expect=(409,))
call("PATCH", f"/api/browser-tests/{test['id']}", json={"safety": {"test_mode_confirmed": True}})
run = call("POST", f"/api/browser-tests/{test['id']}/run")
print("     journey:", run["ok"], run.get("error"), run["duration_ms"], "ms")

site_key = site_d["site_key"]
for _ in range(3):
    r = requests.post(API + "/ingest", data='{"site_key":"%s","type":"js","message":"TypeError: x is undefined user@mail.com","stack":"TypeError\\n at a (app.js:1:2)","page_url":"https://example.com/contact?token=abc"}' % site_key)
print("     ingest:", r.status_code)
errs = call("GET", "/api/errors")
print("     error groups:", len(errs), errs[0]["count"] if errs else None, errs[0]["message"] if errs else None)

incs = call("GET", "/api/incidents")
print("     incidents:", incs["counts"])
if incs["incidents"]:
    iid = incs["incidents"][0]["id"]
    call("PATCH", f"/api/incidents/{iid}", json={"status": "investigating"})
    call("POST", f"/api/incidents/{iid}/notes", json={"text": "Looking into it"})
    ai = call("POST", f"/api/incidents/{iid}/diagnose")
    print("     ai:", ai["engine"], ai["headline"])
rep = call("POST", "/api/reports", json={"client_id": client["id"], "days": 7})
pub = requests.get(API + f"/api/public/reports/{rep['share_token']}")
print("     public report:", pub.status_code, pub.json()["data"]["summary"])
call("GET", "/api/dashboard")
call("GET", "/api/system/health")
call("POST", "/api/workspace/notifications/test")
call("GET", "/api/workspace/audit")
print("SMOKE TEST PASSED")

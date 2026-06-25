"""Quick Cortex bootstrap — runs inside the Cortex container."""
import urllib.request, json, http.cookiejar, sys

BASE = "http://localhost:9001"
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def req(method, path, body=None, csrf=False):
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"} if data else {}
    if csrf:
        headers["Csrf-Token"] = "nocheck"
    r = urllib.request.Request(f"{BASE}{path}", method=method, data=data, headers=headers)
    return opener.open(r, timeout=10)

# 1. Migrate
req("POST", "/api/maintenance/migrate", {})
print("1. DB migrated")

# 2. Create admin
try:
    req("POST", "/api/user", {"login": "admin", "name": "ATTENSE Admin", "password": "Admin123456!", "roles": ["superadmin"]})
    print("2. Admin created")
except Exception:
    print("2. Admin already exists")

# 3. Login
req("POST", "/api/login", {"user": "admin", "password": "Admin123456!"})
print("3. Logged in")

# 4. Create org
try:
    req("POST", "/api/organization", {"name": "ATTENSE", "description": "ATTENSE Cyber Range", "status": "Active"}, csrf=True)
    print("4. Org ATTENSE created")
except Exception as e:
    print(f"4. Org: {e}")

# 5. Create analyst user
try:
    req("POST", "/api/user", {"login": "attense-analyst", "name": "ATTENSE Analyst", "password": "attense-Analyst1!", "organization": "ATTENSE", "roles": ["read", "analyze", "orgadmin"]}, csrf=True)
    print("5. User created")
except Exception as e:
    print(f"5. User: {e}")

# 6. Generate API key
resp = req("POST", "/api/user/attense-analyst/key/renew", {}, csrf=True)
api_key = resp.read().decode().strip().strip('"')
print(f"6. API Key: {api_key}")

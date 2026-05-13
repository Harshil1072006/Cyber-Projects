import urllib.request, json

BASE = 'http://localhost:8001'

def post(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(BASE+path, data=body, headers={'Content-Type':'application/json'}, method='POST')
    r = urllib.request.urlopen(req, timeout=60)
    return json.loads(r.read())

def get(path):
    r = urllib.request.urlopen(BASE+path, timeout=15)
    return json.loads(r.read())

print("=== HEALTH ===")
h = get('/api/health')
print(h)

print("\n=== TOOLS AVAILABLE ===")
tools = get('/api/tools/')
for tid in tools:
    t = tools[tid]
    print("  " + tid + ": " + t["name"] + " (" + t["category"] + ")")

print("\n=== TEST 1: nmap on google.com (ports 80,443) ===")
try:
    r = post('/api/scans/launch', {'target': 'google.com', 'tool': 'nmap', 'options': {'timing': 4, 'service_detection': True, 'ports': '80,443'}})
    print("  scan_id=" + r["scan_id"] + " | status=" + r["status"] + " | findings=" + str(r["findings_count"]))
    sid = r["scan_id"]
    detail = get('/api/scans/' + sid)
    for f in detail.get("findings", []):
        print("  FINDING: [" + f["severity"] + "] " + f["title"])
except Exception as e:
    print("  ERROR: " + str(e))

print("\n=== TEST 2: subfinder on google.com ===")
try:
    r = post('/api/scans/launch', {'target': 'google.com', 'tool': 'subfinder', 'options': {'silent': True}})
    print("  scan_id=" + r["scan_id"] + " | status=" + r["status"] + " | findings=" + str(r["findings_count"]))
    if r["findings_count"] > 0:
        detail = get('/api/scans/' + r["scan_id"])
        for f in detail.get("findings", [])[:5]:
            print("  " + f["title"])
except Exception as e:
    print("  SKIP (not installed or error): " + str(e))

print("\n=== TEST 3: httpx on google.com ===")
try:
    r = post('/api/scans/launch', {'target': 'https://google.com', 'tool': 'httpx', 'options': {'title': True, 'tech_detect': True, 'status_code': True, 'follow_redirects': True}})
    print("  scan_id=" + r["scan_id"] + " | status=" + r["status"] + " | findings=" + str(r["findings_count"]))
    if r["findings_count"] > 0:
        detail = get('/api/scans/' + r["scan_id"])
        for f in detail.get("findings", [])[:3]:
            print("  " + f["title"])
except Exception as e:
    print("  SKIP (not installed or error): " + str(e))

print("\n=== SCAN HISTORY ===")
scans = get('/api/scans/')
print("  Total scans stored: " + str(len(scans)))
for s in scans[:5]:
    print("  [" + s["status"] + "] " + s["tool"] + " -> " + s["target"])

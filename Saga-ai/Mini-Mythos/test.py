import urllib.request
import json
import urllib.error

req = urllib.request.Request(
    'http://127.0.0.1:8081/api/scan',
    data=json.dumps({'target': 'http://demo.testfire.net/'}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)

try:
    response = urllib.request.urlopen(req)
    print("SUCCESS")
    print(response.read().decode())
except urllib.error.HTTPError as e:
    print(f"HTTP ERROR {e.code}")
    print(e.read().decode())
except Exception as e:
    print("OTHER ERROR", str(e))

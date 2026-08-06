import subprocess
import time
import urllib.request
import json

p = subprocess.Popen(['uvicorn', 'main:app', '--port', '8082'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
time.sleep(3)

req = urllib.request.Request(
    'http://127.0.0.1:8082/api/scan',
    data=json.dumps({'target': 'http://demo.testfire.net/'}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)

try:
    urllib.request.urlopen(req)
    print("SUCCESS")
except Exception as e:
    print("FAILED:", e)

p.terminate()
out, err = p.communicate()
print("UVICORN LOGS:")
print(out.decode())

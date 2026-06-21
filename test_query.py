import urllib.request
import urllib.error
import json
import os


HIVE_API_KEY = os.environ.get('HIVE_API_KEY')
if not HIVE_API_KEY:
    raise SystemExit('HIVE_API_KEY must be set in the environment')

req = urllib.request.Request(
    'http://thehive:9000/api/v1/query',
    data=json.dumps({'query': [{'_name': 'listNotifier'}]}).encode(),
    headers={
        'Authorization': f'Bearer {HIVE_API_KEY}',
        'Content-Type': 'application/json'
    }
)

try:
    response = urllib.request.urlopen(req)
    print("SUCCESS CODE:", response.code)
    print(response.read().decode())
except urllib.error.HTTPError as e:
    print("HTTP ERROR:", e.code)
    print(e.read().decode())
except Exception as e:
    print("OTHER ERROR:", e)

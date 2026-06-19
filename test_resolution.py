import json
import os
import urllib.request
import time

BASE = 'http://localhost:8010'

# The /internal/webhook/hive endpoint authenticates callers with TheHive's
# shared bearer secret (matches attense-app's WEBHOOK_SECRET), so present it.
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', 'changeme-webhook')

def post(path, body):
    data = json.dumps(body).encode()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {WEBHOOK_SECRET}',
    }
    req = urllib.request.Request(f'{BASE}{path}', data=data, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def run_tests():
    # Wait for service to be healthy
    for _ in range(15):
        try:
            req = urllib.request.Request(f'{BASE}/health')
            with urllib.request.urlopen(req) as r:
                if json.loads(r.read())['status'] == 'ok':
                    break
        except:
            pass
        time.sleep(1)

    print('=' * 60)
    print('Testing Granular Case Resolutions')
    print('=' * 60)

    cases = [
        ('FalsePositive', 'alert_denied', 'false_positive'),
        ('TruePositive', 'incident_ended', 'success'),
        ('Duplicated', 'alert_denied', 'allowed'),
        ('Indeterminate', 'incident_ended', 'unknown'),
        ('', 'incident_ended', 'unknown'), # missing resolutionStatus
    ]

    all_passed = True
    for resolution, expected_event, expected_outcome in cases:
        status, resp = post('/internal/webhook/hive', {
            'objectType': 'Case',
            'operation': 'Update',
            'object': {
                'id': f'case-{resolution}',
                'tags': ['attense:incident-inc-test-res'],
                'status': 'Resolved',
                'resolutionStatus': resolution
            }
        })
        
        event_type = resp.get('attense_event_type')
        if status == 200 and event_type == expected_event:
            print(f"[PASS] {resolution or 'None':<15} -> {event_type} (expected outcome: {expected_outcome})")
        else:
            print(f"[FAIL] {resolution or 'None':<15} -> returned {event_type} (expected {expected_event}), resp: {resp}")
            all_passed = False

    print('=' * 60)
    if all_passed:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED.")
    print('=' * 60)

if __name__ == '__main__':
    run_tests()

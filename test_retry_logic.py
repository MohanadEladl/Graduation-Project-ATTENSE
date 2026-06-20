import time
import httpx
from core import hive_provisioner


class FakeResp:
    def __init__(self, status_code, body=None, text=None):
        self.status_code = status_code
        self._body = body if body is not None else {"key": "abc123"}
        self.text = text if text is not None else '"abc123"'

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code} error", request=httpx.Request("POST", "http://fake"), response=httpx.Response(self.status_code, request=httpx.Request("POST", "http://fake"))
            )

    def json(self):
        return self._body


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append(("GET", url))
        return self.responses.pop(0)

    def post(self, url, json=None, headers=None):
        self.calls.append(("POST", url))
        return self.responses.pop(0)

    def close(self):
        pass


def run_scenario(name, responses, expect):
    fake_client = FakeClient(responses)
    hive_provisioner._admin_client = lambda: fake_client
    start = time.time()
    try:
        key = hive_provisioner.create_user_in_org("TestOrg", "testuser")
        outcome = f"returned key={key!r}"
    except RuntimeError as exc:
        outcome = f"raised RuntimeError: {exc}"
    elapsed = time.time() - start
    print(f"[{name}] {outcome} | elapsed={elapsed:.2f}s | calls={len(fake_client.calls)} | expect={expect}")


# Scenario A: existing-check 404 -> create 200 -> renew 404,404,200 (retry then succeed)
run_scenario(
    "A: retry-then-succeed",
    [FakeResp(404), FakeResp(200), FakeResp(404), FakeResp(404), FakeResp(200)],
    "success, ~2s elapsed (2 sleeps), 5 calls total",
)

# Scenario B: renew returns 500 on first attempt (non-404) -> raise immediately, no retry
run_scenario(
    "B: non-404-immediate-raise",
    [FakeResp(404), FakeResp(200), FakeResp(500)],
    "RuntimeError, ~0s elapsed (no sleep), 3 calls total",
)

# Scenario C: renew 404 three times -> exhausted -> RuntimeError, ~2s elapsed
run_scenario(
    "C: exhausted-after-3",
    [FakeResp(404), FakeResp(200), FakeResp(404), FakeResp(404), FakeResp(404)],
    "RuntimeError, ~2s elapsed (2 sleeps), 5 calls total",
)

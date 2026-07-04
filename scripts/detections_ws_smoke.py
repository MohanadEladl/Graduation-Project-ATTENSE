"""Smoke-test /ws/detections: connect, read snapshot, inject 1 alert, receive it."""
import asyncio, json, urllib.request
import websockets


def inject_alert() -> None:
    raw = {
        "timestamp": "2026-04-21T00:31:00+0000",
        "rule": {"id": "31104", "level": 9, "description": "SQL injection attempt",
                 "groups": ["web", "sql_injection"]},
        "agent": {"id": "001", "name": "target-agent", "ip": "10.0.0.5"},
        "location": "/var/log/nginx/access.log",
        "full_log": "1.2.3.4 - - GET /login?u=admin'--",
        "data": {"srcip": "1.2.3.4", "dstip": "10.0.0.5"},
    }
    req = urllib.request.Request(
        "http://signal-store:8000/events",
        data=json.dumps(raw).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req).read()


async def go() -> None:
    async with websockets.connect("ws://localhost:8000/ws/detections") as ws:
        first = json.loads(await ws.recv())
        print("[snap]", first.get("type"),
              "count=", len(first.get("data", {}).get("events", [])),
              "reachable=", first.get("data", {}).get("status", {}).get("reachable"))

        await asyncio.sleep(0.5)
        inject_alert()
        print("[inject] alert posted, waiting for broadcast…")

        msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
        m = json.loads(msg)
        print("[push]", m.get("type"), m["data"].get("scenario_id"),
              m["data"].get("metadata", {}).get("description"))


asyncio.run(go())

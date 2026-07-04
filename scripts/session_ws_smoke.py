"""Smoke-test the /ws/sessions/{id} WebSocket end-to-end.

Run inside the red-team-backend container where localhost:8000 = backend.
"""
import asyncio, json, urllib.request
import websockets


def create() -> str:
    req = urllib.request.Request(
        "http://localhost:8000/api/sessions",
        data=json.dumps({"module_id": "brute_force"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req).read())["session_id"]


async def go() -> None:
    sid = create()
    print("sid=", sid)
    async with websockets.connect(f"ws://localhost:8000/ws/sessions/{sid}") as ws:
        await ws.send(json.dumps({"type": "start"}))
        got = 0
        async for msg in ws:
            m = json.loads(msg)
            got += 1
            if m["type"] == "snapshot":
                st = m["data"]["state"]
                print("[snap] state=", st)
                if st in ("completed", "error") and got > 1:
                    break
            elif m["type"] == "log":
                line = m["data"]["line"][:80]
                print("[log]", line)
            if got > 80:
                break


asyncio.run(go())

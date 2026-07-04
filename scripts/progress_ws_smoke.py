"""Verify per-step auto-complete: create brute_force session, stream /ws/sessions/:sid,
   and confirm completed_steps ticks 0→1→2 as engine logs stream, not just at the end.
"""
import asyncio, json, urllib.request
import websockets


def create_session() -> str:
    req = urllib.request.Request(
        "http://localhost:8000/api/sessions",
        data=json.dumps({"module_id": "brute_force"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req).read())["session_id"]


async def go() -> None:
    sid = create_session()
    print("sid=", sid)
    async with websockets.connect(f"ws://localhost:8000/ws/sessions/{sid}") as ws:
        await ws.send(json.dumps({"type": "start"}))
        observed = []
        async for msg in ws:
            m = json.loads(msg)
            if m["type"] == "snapshot":
                cs = m["data"]["completed_steps"]
                st = m["data"]["state"]
                if cs != observed:
                    print(f"[snap] state={st} completed={cs}")
                    observed = list(cs)
                if st in ("completed", "error"):
                    break
        print("final completed=", observed)


asyncio.run(go())

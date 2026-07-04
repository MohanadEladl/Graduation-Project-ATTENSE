"""
WebSocket smoke test for the red-team shell.

Connects to ws://localhost:3000/ws/shell (nginx -> red-team-backend),
collects messages for a few seconds, sends a `help` command, and asserts:
  1. Banner output arrives
  2. A prompt message arrives
  3. Output arrives in response to `help`
"""
import asyncio
import json
import sys

import websockets

# Windows default stdout codec (cp1256 here) chokes on the banner's box-drawing
# glyphs — force UTF-8 so the smoke test can print what it actually received.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

URL = "ws://localhost:3000/ws/shell"


async def main() -> int:
    banner_output = []
    prompts = []
    post_help_output = []
    snapshots = []

    async with websockets.connect(URL, open_timeout=10) as ws:
        # Phase 1: collect initial banner + prompt for up to 3 seconds
        try:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=3.0)
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                t = msg.get("type")
                if t == "output":
                    banner_output.append(str(msg.get("data", "")))
                elif t == "prompt":
                    prompts.append(str(msg.get("data", "")))
                elif t == "snapshot":
                    snapshots.append(msg.get("data"))
        except asyncio.TimeoutError:
            pass

        # Phase 2: send `help` and collect response
        await ws.send(json.dumps({"type": "input", "data": "help"}))
        try:
            while True:
                raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                t = msg.get("type")
                if t == "output":
                    post_help_output.append(str(msg.get("data", "")))
                elif t == "prompt":
                    prompts.append(str(msg.get("data", "")))
        except asyncio.TimeoutError:
            pass

    joined_banner = "\n".join(banner_output)
    joined_help = "\n".join(post_help_output)

    print("=== BANNER OUTPUT ({} msgs) ===".format(len(banner_output)))
    print(joined_banner[:1200])
    print()
    print("=== PROMPTS ({} msgs) ===".format(len(prompts)))
    for p in prompts[:5]:
        print(repr(p))
    print()
    print("=== SNAPSHOTS ({} msgs) ===".format(len(snapshots)))
    if snapshots:
        print(json.dumps(snapshots[0], indent=2)[:600])
    print()
    print("=== POST-HELP OUTPUT ({} msgs) ===".format(len(post_help_output)))
    print(joined_help[:1200])
    print()

    failures = []
    if len(banner_output) == 0:
        failures.append("no banner output received on connect")
    if len(prompts) == 0:
        failures.append("no prompt message received")
    elif not any("attense" in p.lower() for p in prompts):
        failures.append("prompt did not contain 'attense'")
    if len(post_help_output) == 0:
        failures.append("no output received after sending `help`")

    if failures:
        print("FAIL:")
        for f in failures:
            print(" -", f)
        return 1

    print("PASS: banner, prompt, and command-response all work")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

#!/usr/bin/env python3
"""
close_lab.py — Close the ATTENSE lab safely
============================================
Run this instead of a bare `docker compose stop` when you're done with a lab
session. It:

  1. Timestamp-backs-up every EPHEMERAL org secrets file (secrets/*.env) to
     secrets/backups/<name>.<UTC>, then DELETES the original — so org bootstrap/
     runtime secrets don't sit in plaintext at the well-known path while the lab
     is down. The next `python scripts/setup_cortex.py` auto-restores them.
  2. PRESERVES the persistent files (secrets/enrichment.env) — those hold
     externally-issued keys (VirusTotal/AbuseIPDB) that cannot be regenerated.
  3. Stops the Docker stack (`docker compose stop`) — containers stop but volumes
     (TheHive/Cortex/Wazuh data) are kept, so reopening resumes where you left off.

A secrets file is only deleted AFTER its backup is confirmed written — a failed
backup never loses the original.

Usage (from anywhere):
    python scripts/close_lab.py            # backup + delete org secrets, then stop
    python scripts/close_lab.py --no-stop  # just back up + delete secrets, leave stack running
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

# On a Windows host the default console codec (cp1252) can't encode the emoji
# below and would crash mid-run, so force UTF-8.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SECRETS_DIR = PROJECT_ROOT / "secrets"
BACKUP_DIR = SECRETS_DIR / "backups"

# Persistent secrets that must NEVER be deleted (externally-issued keys, etc.).
KEEP_FILES = {"enrichment.env"}


def backup_and_delete_secrets() -> None:
    """Back up (timestamped) then delete each ephemeral secrets/*.env file."""
    print("🗄️  Backing up + removing ephemeral org secrets …")
    if not SECRETS_DIR.is_dir():
        print(f"   ℹ️  No secrets dir at {SECRETS_DIR} — nothing to do.")
        return

    ephemeral = [
        p for p in sorted(SECRETS_DIR.glob("*.env"))
        if p.name not in KEEP_FILES
    ]
    if not ephemeral:
        print("   ℹ️  No ephemeral *.env files to remove (already closed?).")
    for path in ephemeral:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup_path = BACKUP_DIR / f"{path.name}.{stamp}"
        try:
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            backup_path.write_bytes(path.read_bytes())   # confirm backup first
        except Exception as exc:
            print(f"   ⚠️  Backup of {path.name} FAILED ({exc}) — keeping original, not deleting.")
            continue
        try:
            path.unlink()
            print(f"   ✅  {path.name} → backed up to {backup_path.name}, original removed.")
        except Exception as exc:
            print(f"   ⚠️  Backed up {path.name} but could not delete it: {exc}")

    for name in sorted(KEEP_FILES):
        if (SECRETS_DIR / name).exists():
            print(f"   🔒  Kept persistent secret: secrets/{name}")


def stop_stack() -> None:
    """Stop the Docker stack (containers stop; volumes/data are preserved)."""
    print("\n🛑  Stopping the Docker stack (`docker compose stop`) …")
    try:
        subprocess.run(["docker", "compose", "stop"], cwd=str(PROJECT_ROOT), check=True)
        print("   ✅  Stack stopped (data volumes preserved).")
    except FileNotFoundError:
        print("   ⚠️  `docker` not found on PATH — stop the stack manually: docker compose stop")
    except subprocess.CalledProcessError as exc:
        print(f"   ⚠️  `docker compose stop` exited {exc.returncode} — stop it manually if needed.")


def main() -> None:
    print("=" * 60)
    print("  ATTENSE — Close Lab")
    print("=" * 60)
    backup_and_delete_secrets()
    if "--no-stop" not in sys.argv:
        stop_stack()
    else:
        print("\n(--no-stop) Leaving the Docker stack running.")
    print("\n" + "=" * 60)
    print("Lab closed. To reopen: docker compose up -d  &&  python scripts/setup_cortex.py")
    print("(setup_cortex.py auto-restores the org secrets from the latest backup.)")
    print("=" * 60)


if __name__ == "__main__":
    main()

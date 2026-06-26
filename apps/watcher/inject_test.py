"""Inject fake auditd EXECVE lines into a log file for local testing."""
import time, sys, os

LOG = os.getenv("AUDIT_LOG", "fake_audit.log")

commands = [
    # Should be investigation_started (reading logs)
    ["cat", "/var/log/nginx/access.log"],
    ["less", "/var/log/auth.log"],
    ["grep", "-r", "Failed password", "/var/log/"],
    # Should be investigation_started (NOT evidence_preserved)
    ["cat", "/var/log/nginx/error.log"],
    # Should be evidence_preserved (actual hash/copy)
    ["sha256sum", "/var/log/nginx/access.log"],
    ["cp", "/var/log/auth.log", "/tmp/evidence/auth.log"],
    # Should be containment_initiated
    ["iptables", "-A", "INPUT", "-s", "10.0.0.42", "-j", "DROP"],
]

delay = int(sys.argv[1]) if len(sys.argv) > 1 else 5
print(f"[inject] waiting {delay}s before starting...")
time.sleep(delay)

with open(LOG, "a", errors="replace") as fh:
    for i, args in enumerate(commands):
        epoch = time.time()
        a_fields = " ".join(f'a{j}="{v}"' for j, v in enumerate(args))
        line = f'type=EXECVE msg=audit({epoch:.3f}:100{i}): argc={len(args)} {a_fields}\n'
        fh.write(line)
        fh.flush()
        print(f"[inject] t+{i*3}s  {' '.join(args)}")
        time.sleep(3)

print("[inject] done")

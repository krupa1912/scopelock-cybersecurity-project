"""
ScopeLock — Day 2 demo script.

Runs three scenarios against the real lab app so you can see (and show
graders) the pipeline working end-to-end:

  1. A well-behaved assessment plan -> executes, finds real vulns.
  2. A misbehaving plan (out-of-scope, destructive, wrong port, etc.)
     -> everything blocked, nothing executed.
  3. A simulated hijack via the /notes trap page's injected instruction
     -> blocked by the scope enforcer regardless of what the "planner"
     was told to do.

At the end it verifies the ledger's hash chain, then tampers with it on
a COPY to show detection.

Run: python3 demo.py
"""

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lab"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scope"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "agent"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ledger"))

import app as labapp
from enforcer import sign_scope
from planner import MockPlanner
from orchestrator import run_assessment
from ledger import Ledger, LedgerTamperError


def start_lab():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    labapp.init_db()
    t = threading.Thread(
        target=lambda: labapp.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    t.start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    return f"http://127.0.0.1:{port}", port


def make_scope(port):
    s = {
        "allowed_hosts": ["127.0.0.1"],
        "allowed_ports": [port],
        "allowed_schemes": ["http"],
        "allowed_path_prefixes": ["/"],
        "blocked_paths": ["/admin/delete"],
        "allowed_tools": ["header_check", "sqli_probe", "xss_probe", "idor_probe"],
        "allow_public_ip": False,
    }
    s["signature"] = sign_scope(s)
    return s


def auto_approve(action):
    print(f"    [human] approving tier-1 action: {action['tool']} -> {action['url']}")
    return True


def section(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main():
    base, port = start_lab()
    scope = make_scope(port)
    ledger_path = os.path.join(tempfile.gettempdir(), "scopelock_demo_ledger.json")
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
    ledger = Ledger(ledger_path)

    section("SCENARIO 1: Well-behaved assessment plan")
    planner = MockPlanner(lab_base_url=base)
    plan = planner.plan_well_behaved()
    for a in plan:
        if a["tool"] == "idor_probe":
            a["url"] = f"{base}/api/user"
    summary = run_assessment(plan, scope, ledger, approve_fn=auto_approve)
    print(f"\nExecuted: {len(summary['executed'])}   Denied: {len(summary['denied'])}")
    for f in summary["findings"]:
        print(f"  [{f.status.upper():10}] {f.claim}  (tool={f.tool})")

    section("SCENARIO 2: Misbehaving plan (out-of-scope, destructive, etc.)")
    bad_plan = planner.plan_misbehaving()
    summary2 = run_assessment(bad_plan, scope, ledger, approve_fn=auto_approve)
    print(f"\nExecuted: {len(summary2['executed'])}   Denied: {len(summary2['denied'])}")
    for d in summary2["denied"]:
        a, gr = d["action"], d["gate_result"]
        print(f"  [BLOCKED stage={gr.stage:12}] {a['tool']:12} -> {a['url']}  ({gr.reason})")

    section("SCENARIO 3: Simulated hijack via /notes trap page")
    import requests
    notes = requests.get(f"{base}/notes", timeout=3).text
    print("Trap page content includes injected instruction:")
    print("  ...", notes.strip().splitlines()[4].strip(), "...")
    hijack_plan = planner.plan_from_hijack_attempt()
    summary3 = run_assessment(hijack_plan, scope, ledger, approve_fn=auto_approve)
    for d in summary3["denied"]:
        a, gr = d["action"], d["gate_result"]
        print(f"  [BLOCKED stage={gr.stage}] agent tried: {a['tool']} -> {a['url']}")
        print(f"  reason: {gr.reason}")
    print(f"\nExecuted: {len(summary3['executed'])}   Denied: {len(summary3['denied'])}")

    section("LEDGER VERIFICATION")
    ok, msg = ledger.verify_chain()
    print(f"Original ledger ({len(ledger)} entries): {msg}")

    tampered_path = os.path.join(tempfile.gettempdir(), "scopelock_demo_ledger_tampered.json")
    shutil.copy(ledger_path, tampered_path)
    with open(tampered_path) as f:
        raw = json.load(f)
    # Flip a denied-action's gate decision to "allowed" to simulate
    # an attacker hiding a blocked attack from the audit trail.
    for entry in raw:
        if entry["entry_type"] == "gate_decision" and entry["data"]["allowed"] is False:
            entry["data"]["allowed"] = True
            entry["data"]["reason"] = "tampered: looks clean now"
            break
    with open(tampered_path, "w") as f:
        json.dump(raw, f, indent=2)

    try:
        Ledger(tampered_path)
        print("Tampered ledger: NO TAMPERING DETECTED (this would be a bug)")
    except LedgerTamperError as e:
        print(f"Tampered ledger: TAMPERING DETECTED -> {e}")

    section("DONE")
    print(f"Full ledger written to: {ledger_path}")


if __name__ == "__main__":
    main()

# ScopeLock

**An AI Agent for Controlled Penetration-Testing Workflows**
CS3405 — Ethical Hacking and Penetration Testing · ByteSecure Hackathon

ScopeLock is an AI pentesting agent built around one idea: **the agent
should never need to be trustworthy for the system to be safe.** Every
action the agent proposes — whether from a real LLM or a scripted
planner — passes through deterministic, non-AI code (a signed scope
allowlist, a risk-tier gate, and an evidence-gated verifier) before
anything actually runs. Destructive actions are architecturally
blocked, not just discouraged. Every decision is written to a
tamper-evident, hash-chained ledger.

All testing happens against a self-built, intentionally vulnerable lab
application running only on `127.0.0.1` — no external or production
systems are ever touched.

---

## 1. File Structure

## Status: Day 4 (judge-facing demos) complete

- [x] Project structure
- [x] Vulnerable lab app with 10 seeded vulnerabilities (`lab/app.py`,
      `lab/GROUND_TRUTH.md`)
- [x] Signed scope definition + enforcer (`scope/enforcer.py`,
      `scope/make_scope.py`)
- [x] Risk-tier gate: tier-0 auto-run, tier-1 human approval, tier-2
      always blocked (`agent/gate.py`)
- [x] Hash-chained, tamper-evident ledger (`ledger/ledger.py`)
- [x] Scope-checked HTTP client that re-validates on every redirect hop
      (`tools/http_client.py`)
- [x] Tool wrappers: header_check, port_check, sqli_probe, xss_probe,
      idor_probe (`tools/`)
- [x] Mock planner (well-behaved, misbehaving, and hijack-simulation
      modes) + LLM-ready planner with strict JSON schema validation
      (`agent/planner.py`)
- [x] Evidence-gated verifier — claims are only "confirmed" when backed
      by real tool evidence (`agent/verifier.py`)
- [x] Orchestrator wiring plan -> gate -> tools -> ledger -> verifier
      (`agent/orchestrator.py`)
- [x] 105 passing tests, including an end-to-end suite against the real
      lab app (`tests/`), plus `demo.py` for a live walkthrough
- [x] Hardened "secure" mirror lab for false-positive measurement
      (`lab/app_secure.py`)
- [x] 33-case misbehavior test suite (`tests/test_misbehavior_suite.py`)
- [x] Ablation test: guardrails on vs off (`tests/test_ablation.py`)
- [x] False-positive suite against the secure lab
      (`tests/test_false_positives.py`)
- [x] Metrics collection script producing `report/results.json`
      (`report/metrics.py`)
- [x] Self-contained HTML report with inline SVG charts, no external
      dependencies (`report/generate_report.py` ->
      `report/scopelock_report.html`)
- [x] Documented limitations (`LIMITATIONS.md`)
- [x] **Live, judge-controlled hijack console** (`live_hijack_console.py`)
      — the judge types any instruction and watches it go through the
      real planner, gate, and verifier live, with no scripting
- [x] **LLM overconfidence demo** (`llm_overconfidence_demo.py`) — shows
      an LLM (real or simulated) making a confident claim, and the
      evidence-gated verifier correctly rejecting it when the real
      tool evidence doesn't support it
- [x] Optional real-LLM integration (`agent/llm_client.py`) — set
      `ANTHROPIC_API_KEY` to drive the planner with a real model;
      degrades gracefully to a clearly-labeled simulated planner
      (`agent/simulated_llm.py`) with no key or no network
- [x] 123 passing tests, including integration tests that prove the
      overconfidence-catching thesis programmatically, not just via a
      demo script's printed output
- [ ] Demo rehearsal / slide prep (not code — see "Presenting" below)

## Judge-facing live demos

**1. Live Hijack Console** — the judge drives the input:
```bash
python3 live_hijack_console.py
```
Type anything: "attack 10.0.0.5", "delete everything", "test the login
for SQL injection". The gate decides what actually runs, not the judge
and not the planner. Every action is traced live: proposed -> scope
check -> tier check -> (approval) -> executed -> evidence -> verified.

**2. LLM Overconfidence Demo** — proves the "don't trust the LLM" thesis:
```bash
python3 llm_overconfidence_demo.py
```
Runs 3 cases (2 real vulnerabilities, 1 on the secure/no-vuln lab) and
shows, side by side: what the tool actually found, what the LLM
claimed, and what the verifier decided. Case 3 is the key moment — a
confident LLM claim on an app with no real vulnerability gets
downgraded by the verifier.

**Using a real LLM instead of the simulated fallback:**
```bash
export ANTHROPIC_API_KEY=your-key-here   # optional
python3 live_hijack_console.py
python3 llm_overconfidence_demo.py
```
Both scripts announce which mode they're using (`REAL LLM` or
`SIMULATED LLM`) at startup, and the simulated fallback is never
silently substituted without saying so.

## Results summary (from `report/results.json`)

| Metric | Value |
|---|---|
| Recall (4 tool-covered vuln categories) | 100% (4/4) |
| False positive rate (secure lab, 4 checks) | 0% (0/4) |
| Misbehaving actions blocked (33-case suite) | 100% (33/33) |
| Attack success rate, with guardrails | 0% |
| Attack success rate, without guardrails (baseline) | 100% |
| Blocked by scope check alone | 24/33 |
| Additionally blocked by the tier system | 9/33 |
| Avg. scope-check overhead | ~0.006 ms |

## Regenerating the report

```bash
python3 report/metrics.py          # writes report/results.json
python3 report/generate_report.py  # writes report/scopelock_report.html
```
Open `report/scopelock_report.html` directly in any browser — it's a
single self-contained file, no server or internet connection needed.

## Demo

```bash
python3 demo.py
```

Runs three scenarios against the real lab app: a well-behaved plan that
finds real vulnerabilities, a misbehaving plan that gets fully blocked,
and a simulated prompt-injection hijack via the `/notes` trap page that
gets blocked regardless of what the planner was told to do. Ends by
tampering with a copy of the ledger to show detection.

## Setup

```bash
pip install -r requirements.txt
```

## Run the lab app (for manual exploration)

```bash
cd lab && python3 app.py
# visit http://127.0.0.1:5000
```

## Generate / regenerate the signed scope file

```bash
cd scope && python3 make_scope.py
```

Run this any time `scope/make_scope.py`'s `build_scope()` changes. Never
hand-edit `scope.json` — the enforcer will reject it because the
signature won't match (see `test_tampered_scope_rejected`).

## Run tests

```bash
python3 -m pytest tests/ -v
```

## Project layout

```
lab/        vulnerable Flask app + secure mirror + GROUND_TRUTH.md
scope/      signed scope.json + enforcer.py (the trust boundary)
tools/      http_client.py (redirect-safe scope checks) + tool wrappers
agent/      gate.py (risk tiers), planner.py, verifier.py, orchestrator.py,
            llm_client.py (real LLM, optional), simulated_llm.py (fallback)
ledger/     hash-chained audit ledger
report/     metrics.py, generate_report.py -> scopelock_report.html
tests/      123 tests: unit + end-to-end + ablation + false-positive +
            LLM-overconfidence integration tests
demo.py                     scripted 3-scenario walkthrough
live_hijack_console.py      judge-controlled live demo
llm_overconfidence_demo.py  LLM-trust thesis demo
LIMITATIONS.md              honest writeup of known gaps
```

## Safety notes

- `lab/` uses only synthetic data (fake usernames, fake "secrets").
- `/admin/delete` exists only so scope's `blocked_paths` has something
  real to deny — it does nothing and always returns 403.
- The lab must only be run locally or inside the project's own Docker
  network, never exposed publicly.
- `scope/enforcer.py` fails closed: any error loading or parsing the
  scope file results in denial, not silent allow.

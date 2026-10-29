# ScopeLock — Known Limitations

Honest accounting of what this prototype does and does not cover, for
the rubric's "limitations" requirement and for anyone extending this
project later.

## Detection coverage

Only 4 of the lab's 10 seeded vulnerability categories have a dedicated
automated probe:

| Covered | Not covered (documented, not probed) |
|---|---|
| V1 SQL injection (auth bypass) | V3 Stored XSS (no dedicated stored-XSS tool; only reflected XSS is probed) |
| V2 Reflected XSS | V5 Verbose error / stack trace leakage |
| V4 Missing security headers | V7 Exposed fake-sensitive file |
| V6 IDOR | V8 Weak session cookie flags |
| | V9 Unauthenticated admin panel |
| | V10 Missing rate limiting |

Recall is reported only against the 4 covered categories (100% on this
subset) rather than against all 10, since claiming recall over
categories nothing was built to detect would be misleading.

## Ablation methodology

The "without guardrails" baseline used in `report/metrics.py` is a
**counterfactual**, not a literal unguarded execution: it assumes 100%
of proposed misbehaving actions would execute if no check existed at
all. We did not actually run the destructive/out-of-scope cases against
real infrastructure unguarded, since doing so would violate this
project's own responsible-testing rules (no attacks on out-of-scope
hosts, no destructive actions, ever). The comparison is therefore
illustrative of what an unguarded pipeline *would* allow, based on the
fact that a naive planner-&gt;tool wiring has no decision point at which
it would refuse.

## Scope enforcer: DNS resolution timing

`scope/enforcer.py` resolves a hostname's IP once per `check_action()`
call. A sufficiently fast DNS-rebinding attack — where the DNS record
changes between the scope check's resolution and the actual HTTP
connection — is not fully closed by this prototype. A more complete
fix would resolve once and pin that specific IP for the socket
connection itself (not just for the scope decision), so the check and
the connection can never observe different IPs. This is a known gap,
not an oversight we are hiding.

## Non-destructive payloads only

All active probes (`sqli_probe`, `xss_probe`, `idor_probe`) use
non-destructive, evidence-producing payloads by design (per the
responsible-testing rules). This means:
- Blind or time-based SQL injection (where the only signal is a
  response-time difference, not a visible auth bypass or error string)
  is not detected by `sqli_probe` as currently implemented.
- DOM-based XSS (no server round-trip involved) is out of scope for
  `xss_probe`, which only checks server-side reflection.
- Second-order IDOR (where the leak surfaces through a different
  endpoint than the one queried) is not covered by `idor_probe`.

## Single-lab evaluation

All metrics are measured against one synthetic lab application and its
secure mirror. Generalization to other codebases, frameworks, or real
applications with different vulnerability patterns has not been tested.

## LLM planner is schema-validated, not semantically verified

`agent/planner.py`'s `LLMPlanner` strictly validates that the LLM's
output is well-formed JSON matching the expected action schema. It does
not independently verify that the LLM's stated `reason` for an action is
truthful or sensible — a malformed or dishonest-but-schema-valid
`reason` string would still pass validation. The actual safety
enforcement happens entirely downstream, in the scope enforcer and risk
gate, which do not trust the `reason` field at all. This is intentional
(never trust the LLM's self-report), but worth stating explicitly.

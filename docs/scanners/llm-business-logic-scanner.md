# LLM Business Logic Scanner

**Type:** LLM-guided DAST | **Severity:** Medium to Critical | **Category:** Auth Weakness | **Needs:** API key, two sessions

## What It Does

Reads the business-logic source files (routers, services, payment and webhook code), asks the LLM for a small set of attack plans, runs each plan's HTTP steps against the live app as the admin or regular user, then asks a judge LLM whether the attack worked. Every step URL is resolved against the target (relative URLs are made absolute) and refused when it leaves the target's scheme, host and port; redirects are re-checked hop by hop.

## Conclusive vs. inconclusive evidence

Between executing the steps and calling the judge, a deterministic gate (`evidence_gap` in `engine/shared/verdict.py`) checks that the replies can support a verdict at all:

- **Inconclusive** (the judge is not called): no step got a response (timeout, connection error, status 0), or every reply was a server error, a missing endpoint, an HTML page, or a request rejected by validation (HTTP 400, 415, 422). The plan is recorded in `skipped_steps` with the reason and reaches `DeepScanReport.scanner_errors`, so a scan that could not test a plan never reads as a clean pass. Individual steps with no response are also listed.
- **Not proven** (the judge is not called): every usable reply was a denial (401, 403) or a `{"success": false}` / `{"error": ...}` style failure. This is a real "not vulnerable", so nothing is recorded.
- Otherwise the judge decides, as before. An empty 2xx is still evidence: an unauthorized DELETE or PATCH legitimately returns no body.

A transport failure is therefore never treated as "safe", and never fed to the judge as if it were an application answer.

Shared rules (module docstring of `engine/shared/verdict.py`): a proof is a response body that differs from a control, never a status-code change or a reflected input.

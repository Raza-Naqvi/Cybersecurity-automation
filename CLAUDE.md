# Security Toolkit - Core Context & Instructions

## 🎯 Project Overview

- **Description:** Python toolkit that automates the black-box side of our security playbook — external recon, auth/session checks, and an IDOR tester — against sites we own or are explicitly authorized to test.
- **Engagement model:** there's a deal between our security team and dev team — dev does not share source code or server access with security. We test as an external black-box tester (HTTP(S) against the running app only) and share findings with dev at the end. Every check in the normal workflow must work without filesystem, DB, or server-shell access.
- **Current Status:** Full Phase 4 recon/testing coverage is implemented and tested, all pure black-box: recon (`fingerprint.py`), auth/session testing (`session_testing.py`), the IDOR tester, injection testing (`injection_testing.py`), upload testing (`upload_testing.py`), business-logic testing (`business_logic_testing.py` — price tamper, coupon reuse, rate limiting, forged webhooks), and infra checks (`infra_testing.py`, wrapping testssl.sh/nikto). Every category from the playbook's Phase 4 methodology now has a module. The IDOR tester's login is config-driven (`auth.type` in scope.json: `wordpress` / `form_session` / `json_token`, or a one-off adapter for anything else) so it works across WordPress, Laravel, and custom Node/Express sites without new code per site. Older white-box checks (Phase 1 incident triage, monthly checklist) were moved to `legacy_whitebox/` — not usable under the current deal, kept only for a possible future white-box engagement.

## 🛠️ Tech Stack & Versioning

- **Core Languages:** Python 3.11+
- **Frameworks:** None (plain stdlib + a few focused libraries) — no web framework, this is CLI tooling.
- **Database / State:** None in the normal workflow — black-box checks never touch a DB. (`legacy_whitebox/` has read-only PyMySQL access, but that package isn't used under the current engagement.) No state of its own beyond JSON/HTML reports written to `reports/`.
- **Key libraries:** `requests` (all HTTP checks), `Jinja2` (report rendering), `python-dotenv` (env loading), `pytest` + `pytest-cov` (tests).

## ⚡ Critical Commands (Build & Run)

- **Install:** `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && pip install -e .`
- **Add a target:** `python scripts/manage_scope.py add` (interactive) — never hand-edit `config/scope.json`.
- **Run — recon:** `python scripts/run_recon.py --target <name-from-scope.json>`
- **Run — auth/session test:** `python scripts/run_auth_test.py --target <name> --protected-path /account --logout-path /logout`
- **Run — IDOR test:** `python scripts/run_idor_test.py --target <name> --cases config/idor_cases/<name>.json`
- **Run — injection test:** `python scripts/run_injection_test.py --target <name> --points config/injection_points/<name>.json`
- **Run — upload test:** `python scripts/run_upload_test.py --target <name> --cases config/upload_cases/<name>.json`
- **Run — business logic test:** `python scripts/run_business_logic_test.py --target <name> --cases config/business_logic_cases/<name>.json`
- **Run — infra test:** `python scripts/run_infra_test.py --target <name>` (needs `testssl.sh`/`nikto` installed separately)
- **Run — legacy/white-box (not used under current engagement):** `python scripts/legacy_whitebox/run_incident_triage.py --target <name>`
- **Test Suite:** `python -m pytest -q`
- **Coverage:** `python -m pytest --cov=security_toolkit --cov-report=term-missing`
- **Format / Lint:** none configured yet — if you add one, use `ruff` and wire it into this section.

## 📐 Architecture & Folder Structure

- `src/security_toolkit/config.py` -> The authorization gate. Loads `config/scope.json` and env vars. Every check resolves its target through here — never hardcode a path/URL elsewhere.
- `src/security_toolkit/scope_guard.py` -> Shared "never request a URL outside the target's base_url" check, used by every HTTP-based module.
- `src/security_toolkit/scope_manager.py` -> Pure add/upsert/remove/save logic for `config/scope.json`, behind `scripts/manage_scope.py`. Nothing should hand-edit scope.json directly anymore.
- `src/security_toolkit/recon/fingerprint.py` -> Phase 4.2 black-box recon: exposed sensitive files, tech-stack fingerprinting via headers/cookies, missing security headers, xmlrpc.php exposure, robots.txt/sitemap.xml. HTTP-only.
- `src/security_toolkit/recon/auth.py` -> Pluggable login adapters selected by `auth.type` in scope.json (`wordpress`, `form_session`, `json_token`). Add a new type here only if no existing adapter fits; otherwise it's config, not code.
- `src/security_toolkit/recon/provision.py` -> Creates the two disposable IDOR test accounts via a site's own public signup endpoint (`register_via_api`). Invite-only sites stay manual — ask dev for credentials only, never code/server access.
- `src/security_toolkit/recon/session_testing.py` -> Phase 4.3 auth/session checks: session fixation, logout invalidation, login rate-limiting. Reuses the same `AuthProvider` adapters as the IDOR tester. HTTP-only.
- `src/security_toolkit/recon/idor_tester.py` -> Phase 4.4 two-account IDOR test, automated across a list of endpoints. GET-only by default. HTTP-only.
- `src/security_toolkit/recon/injection_testing.py` -> Phase 4.5 SQLi/NoSQLi/XSS payload sweeps against a named parameter. Error-signature matching + unescaped-reflection detection — a signal for manual confirmation, not a final verdict. Read-only payloads only (no DROP/UPDATE/DELETE). HTTP-only.
- `src/security_toolkit/recon/upload_testing.py` -> Phase 4.6 file-upload testing: extension bypass, content-type spoof, GIF/PHP polyglot, path traversal. Two signals — "accepted" and "executed" (the one that matters) — via a unique per-run marker. HTTP-only.
- `src/security_toolkit/recon/business_logic_testing.py` -> Phase 4.7: price/quantity tampering, coupon/discount reuse, rate-limited one-time actions, forged webhook events (no valid signature). Config-driven per case — doesn't infer app logic on its own. HTTP-only.
- `src/security_toolkit/recon/infra_testing.py` -> Phase 4.8: wraps `testssl.sh` (TLS/cert) and `nikto` (general misconfig) via subprocess against base_url. Neither tool ships with this repo.
- `src/security_toolkit/legacy_whitebox/` -> NOT used under the current engagement — needs filesystem/DB/WP-CLI access. Kept for a possible future white-box engagement only. Never add new checks here unless the engagement model has explicitly changed.
- `src/security_toolkit/reporting/report.py` -> Turns a list of `Finding`s into JSON + HTML under `reports/`.
- `scripts/` -> Thin CLI entrypoints (argparse) that wire config + checks + reporting together. `scripts/legacy_whitebox/` mirrors the package split above.
- `config/scope.example.json` -> Template for the allowlist, with one example `auth` block per site type. Real `config/scope.json` is gitignored.
- `tests/` -> Mirrors `src/security_toolkit/` structure 1:1, including the `legacy_whitebox/` split.

## 🚧 Strict Rules & Guardrails ("What NOT to do")

- **Never** add a check to the normal workflow (`recon/`, `scripts/` outside `legacy_whitebox/`) that needs filesystem, DB, or server-shell access. That access does not exist under the current security/dev engagement — if a check needs it, it belongs in `legacy_whitebox/`, clearly marked, and should not be wired into any non-legacy script.
- **Never** add a check that acts on a target not resolved through `security_toolkit.config.load_authorized_target`. If a script doesn't call it, that's a bug.
- **Never** run anything in this repo against a live production site. Every script in here is meant for a staging/local copy per the playbook's safety rule — if you need a production exception, get a second person's sign-off and say so explicitly in the PR.
- **Never** hardcode credentials or API keys — read from `.env` via `security_toolkit.config.load_credentials_from_env` (test accounts) or `load_db_config` (legacy only), never inline.
- **Never** have a check silently mutate or delete anything (files, DB rows, accounts). Account creation is the one explicit exception (provisioning the two disposable IDOR test accounts), and even that only through the site's own public signup flow.
- **Never** let any HTTP-based check call a URL that isn't validated through `security_toolkit.scope_guard.require_in_scope`/`resolve_in_scope_url` against the target's `base_url`.
- **Never** commit `config/scope.json`, `.env`, `config/idor_cases/`, or anything under `reports/` — they're gitignored for a reason; don't force-add them.

## ⚙️ Custom Coding Standards & Workflows

- **Step 1 (Plan):** Before adding a new check, confirm which playbook phase/section it automates (see `docs/security-playbook.md`) and whether it can run purely over HTTP(S) — if not, it's `legacy_whitebox/` material, not the normal workflow.
- **Step 2 (TDD):** Write the test in `tests/` first for any pure-logic function (parsing, filtering, scoring). Only subprocess/DB/network calls get mocked rather than test-first — run `python -m pytest -q` before and after every change. Target 80%+ coverage (`--cov-report=term-missing` to see gaps).
- **Step 3 (Style):** Dataclasses are `frozen=True` (immutable results — never mutate a returned object, build a new one). Type-hint every function signature. Functions stay small and single-purpose; a new concern gets a new function, not a longer one. Validate all paths/inputs at the top of a function and fail fast with a clear exception.

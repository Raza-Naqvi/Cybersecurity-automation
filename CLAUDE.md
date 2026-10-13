# Security Toolkit - Core Context & Instructions

## 🎯 Project Overview

- **Description:** Python toolkit that automates the black-box side of our security playbook — external recon, auth/session checks, and an IDOR tester — against sites we own or are explicitly authorized to test.
- **Engagement model:** there's a deal between our security team and dev team — dev does not share source code or server access with security. We test as an external black-box tester (HTTP(S) against the running app only) and share findings with dev at the end. Every check in the normal workflow must work without filesystem, DB, or server-shell access.
- **Current Status:** Full Phase 4 recon/testing coverage is implemented and tested, all pure black-box, plus the extras below. Core checks: recon (`fingerprint.py`), auth/session testing (`session_testing.py`), the IDOR tester (+ sequential-ID enumeration), injection testing (`injection_testing.py` — SQLi/NoSQLi/XSS/template injection), SSRF (`ssrf_testing.py`, via webhook.site OOB callbacks), JWT tampering (`jwt_testing.py` — claims, alg=none bypass, weak-secret brute force, RS256→HS256 confusion, storage hints), upload testing (`upload_testing.py`), business-logic testing (`business_logic_testing.py`), infra checks (`infra_testing.py` — testssl.sh/nikto required, plus an optional `nuclei` CVE-template scan), and two optional external-tool recon wrappers wired automatically into `run_recon.py` — subdomain enumeration (`subdomain_enum.py`, via `subfinder`) and directory/file brute-forcing (`dir_enum.py`, via `dirsearch`). All of this toolkit's external-tool wrapping is documented tool-by-tool in `docs/pentest-tools-howto.md`. A shared rate-limit probe (`rate_limit_check.py`) is wired automatically into IDOR/injection/upload/business-logic/login checks — every endpoint this toolkit touches gets that signal, not just login. The IDOR tester's login is config-driven (`auth.type`: `wordpress` / `form_session` / `json_token`) so it works across WordPress, Laravel, and custom Node/Express sites without new code per site, and `auth_detect.py`/`manage_scope.py add --auth-type auto` can auto-fill that block from just a login URL. Test-account credentials live in MongoDB (`credentials_db.py`), keyed by target name + label, populated via `provision_test_accounts.py` or `manage_credentials.py`. Every report uploads to Cloudinary (`reporting/cloud_report.py`) and gets indexed in MongoDB (`report_index.py`, including the full findings list) — nothing written to local disk. `scripts/doctor.py` checks and auto-fixes a machine's setup, cross-platform. `scripts/run_all_tests.py` runs every check for one target in one command, front-loading its one possible question (account creation) before anything executes, and finishes by generating a consolidated findings draft (`findings_report.py` / `scripts/generate_findings_report.py`) — aggregation is automatic, the human sign-off before sending to dev stays manual by design. Older white-box checks were moved to `legacy_whitebox/` — not usable under the current deal.

## 🛠️ Tech Stack & Versioning

- **Core Languages:** Python 3.11+
- **Frameworks:** None (plain stdlib + a few focused libraries) — no web framework, this is CLI tooling.
- **Database / State:** None of the target app's — black-box checks never touch it. (`legacy_whitebox/` has read-only PyMySQL access to the target's DB, but that package isn't used under the current engagement.) The toolkit's OWN state: test-account credentials AND the report index in MongoDB — local instance or a private Atlas cluster, set via `MONGODB_URI` in `.env`, never the target app's DB. No local disk state at all for reports — they upload straight to Cloudinary (`CLOUDINARY_URL` in `.env`).
- **Key libraries:** `requests` (all HTTP checks), `pymongo` + `dnspython` (credential/report-index store, the latter needed for `mongodb+srv://` Atlas URIs), `cloudinary` (report storage), `Jinja2` (report rendering), `python-dotenv` (env loading), `pytest` + `pytest-cov` (tests).

## ⚡ Critical Commands (Build & Run)

- **Install:** `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && pip install -e .`
- **Check/fix a machine's setup:** `python scripts/doctor.py` — run this first on any new machine; `--check-only` to just report.
- **Add a target:** `python scripts/manage_scope.py add` (interactive) — never hand-edit `config/scope.json`.
- **Run everything for a target:** `python scripts/run_all_tests.py --target <name> --register-url <url> --protected-path <path> --logout-path <path>` — the normal day-to-day command.
- **Provision test accounts:** `python scripts/provision_test_accounts.py --target <name> --register-url <url>` — auto-creates both, saves credentials to MongoDB.
- **Manage credentials by hand:** `python scripts/manage_credentials.py add --target <name> --label IDOR_USER_A`
- **Run — recon:** `python scripts/run_recon.py --target <name-from-scope.json>`
- **Run — auth/session test:** `python scripts/run_auth_test.py --target <name> --protected-path /account --logout-path /logout`
- **Run — IDOR test:** `python scripts/run_idor_test.py --target <name> --cases config/idor_cases/<name>.json`
- **Run — injection test:** `python scripts/run_injection_test.py --target <name> --points config/injection_points/<name>.json`
- **Run — upload test:** `python scripts/run_upload_test.py --target <name> --cases config/upload_cases/<name>.json`
- **Run — business logic test:** `python scripts/run_business_logic_test.py --target <name> --cases config/business_logic_cases/<name>.json`
- **Run — SSRF test:** `python scripts/run_ssrf_test.py --target <name> --points config/injection_points/<name>.json`
- **Run — JWT test:** `python scripts/run_jwt_test.py --target <name> --token <captured-jwt> --protected-path /account`
- **Run — infra test:** `python scripts/run_infra_test.py --target <name>` (needs `testssl.sh`/`nikto` installed separately)
- **Generate a findings draft:** `python scripts/generate_findings_report.py --target <name>` — aggregates every flagged finding on record for the target
- **Run — legacy/white-box (not used under current engagement):** `python scripts/legacy_whitebox/run_incident_triage.py --target <name>`
- **Test Suite:** `python -m pytest -q`
- **Coverage:** `python -m pytest --cov=security_toolkit --cov-report=term-missing`
- **Format / Lint:** none configured yet — if you add one, use `ruff` and wire it into this section.

## 📐 Architecture & Folder Structure

- `src/security_toolkit/config.py` -> The authorization gate. Loads `config/scope.json` and env vars. Every check resolves its target through here — never hardcode a path/URL elsewhere.
- `src/security_toolkit/scope_guard.py` -> Shared "never request a URL outside the target's base_url" check, used by every HTTP-based module.
- `src/security_toolkit/scope_manager.py` -> Pure add/upsert/remove/save logic for `config/scope.json`, behind `scripts/manage_scope.py`. Nothing should hand-edit scope.json directly anymore.
- `src/security_toolkit/credentials_db.py` -> MongoDB-backed test-account credential store, keyed by `(target_name, label)`. This is the toolkit's own private storage — never the target app's DB. Read via `config.load_test_credentials`.
- `src/security_toolkit/report_index.py` -> MongoDB index of every report ever uploaded (target, title, timestamp, Cloudinary URLs, flagged) — for the planned dashboard. Written to automatically by `reporting/cloud_report.py`.
- `src/security_toolkit/doctor_checks.py` -> Pure logic behind `scripts/doctor.py`: OS/package-manager detection, individual check results, install-command builders. No installing/network calls here — that's the thin CLI's job, kept testable without side effects.
- `src/security_toolkit/tool_locations.py` -> Resolves `testssl.sh`/`nikto`/`dirsearch`/`subfinder`/`nuclei`: PATH first, then (for the ones that can run straight from a git clone) a `vendor/` copy `doctor.py` may have cloned in; `subfinder`/`nuclei` are PATH-only, no vendoring fallback, since both are compiled Go binaries. Shared by `infra_testing.py`/`subdomain_enum.py`/`dir_enum.py` (to run them) and `doctor.py` (to check/install them) so both agree on where to look.
- `src/security_toolkit/orchestrator.py` -> Pure "what to run, what to skip, and why" decision logic behind `scripts/run_all_tests.py`. Given what's already set up for a target, decides the whole plan up front — this is what lets that script ask its one possible question before anything runs, not mid-way through.
- `src/security_toolkit/findings_report.py` -> Pulls every flagged finding on record for a target from `report_index.py` and renders one consolidated Markdown draft, grouped by scan type. Aggregation only — impact/fix/send-to-dev stays a human call, by design.
- `src/security_toolkit/recon/rate_limit_check.py` -> Shared rate-limit probe (fire N requests, look for an HTTP 429). `session_testing.py`/`business_logic_testing.py` delegate to it explicitly; `idor_tester.py`/`injection_testing.py`/`upload_testing.py` wire it in automatically per case/point so every endpoint tested gets this signal.
- `src/security_toolkit/env_file.py` -> Merge-in-place `.env` updates — only used by the legacy env-based credential fallback now.
- `src/security_toolkit/recon/html_forms.py` -> Shared regex-based `<form>` parsing used by both `auth_detect.py` and `provision.py`'s `register_via_form`. Add new form-reading logic here, not duplicated in either caller.
- `src/security_toolkit/recon/auth_detect.py` -> Auto-detects a login page's form fields (+ CSRF token) into an `auth` block — the `auto` option in `manage_scope.py add --auth-type`. HTML forms only; `json_token` still needs manual setup.
- `src/security_toolkit/recon/fingerprint.py` -> Phase 4.2 black-box recon: exposed sensitive files, tech-stack fingerprinting via headers/cookies, missing security headers, xmlrpc.php exposure, robots.txt/sitemap.xml. HTTP-only.
- `src/security_toolkit/recon/subdomain_enum.py` -> Phase 4.2: wraps the external `subfinder` tool (passive subdomain discovery via public sources only) for the target's own domain, derived from `base_url` — never a free-form domain. Wired into `run_recon.py` automatically (`--skip-subdomain-enum` to opt out). See `docs/pentest-tools-howto.md` §8.2.
- `src/security_toolkit/recon/dir_enum.py` -> Phase 4.2: wraps the external `dirsearch` tool (wordlist-based path brute-force) against the target's `base_url` — a deeper, slower generalization of `fingerprint.check_exposed_files`'s fixed list. Wired into `run_recon.py` automatically (`--skip-dir-enum` to opt out). See `docs/pentest-tools-howto.md` §2.5.
- `src/security_toolkit/recon/auth.py` -> Pluggable login adapters selected by `auth.type` in scope.json (`wordpress`, `form_session`, `json_token`). Add a new type here only if no existing adapter fits; otherwise it's config, not code.
- `src/security_toolkit/recon/provision.py` -> Creates the two disposable IDOR test accounts via a site's own public signup — `register_via_form` auto-detects an HTML registration form (reuses `html_forms.py`), `register_via_api` posts a JSON payload. Invite-only sites stay manual — ask dev for credentials only, never code/server access, then store them with `manage_credentials.py`.
- `src/security_toolkit/recon/session_testing.py` -> Phase 4.3 auth/session checks: session fixation, logout invalidation, login rate-limiting. Reuses the same `AuthProvider` adapters as the IDOR tester. HTTP-only.
- `src/security_toolkit/recon/idor_tester.py` -> Phase 4.4 two-account IDOR test, automated across a list of endpoints, plus `check_sequential_id_enumeration` (nearby IDs, confirms a dataset-wide walkable exposure vs. a one-off). GET-only by default. HTTP-only.
- `src/security_toolkit/recon/injection_testing.py` -> Phase 4.5 SQLi/NoSQLi/XSS/template-injection payload sweeps against a named parameter. Error-signature/evaluated-output matching + unescaped-reflection detection — a signal for manual confirmation, not a final verdict. Read-only payloads only. HTTP-only.
- `src/security_toolkit/recon/ssrf_testing.py` -> Phase 4.5 SSRF via out-of-band confirmation: sends a disposable webhook.site callback URL, polls for a hit. A confirmed hit means the server actually made the outbound request — not a guess.
- `src/security_toolkit/recon/jwt_testing.py` -> Phase 4.3 JWT tampering: claim checks, `alg: none` bypass, weak-secret HS256 brute force (built-in wordlist, pure crypto), RS256→HS256 confusion, and a storage hint (JWT-shaped cookie missing HttpOnly, or token-in-JSON-body = localStorage risk) — the latter read straight from HTTP headers, no browser needed.
- `src/security_toolkit/recon/upload_testing.py` -> Phase 4.6 file-upload testing: extension bypass, content-type spoof, GIF/PHP polyglot, path traversal. Two signals — "accepted" and "executed" (the one that matters) — via a unique per-run marker. HTTP-only.
- `src/security_toolkit/recon/business_logic_testing.py` -> Phase 4.7: price/quantity tampering, coupon/discount reuse, rate-limited one-time actions, forged webhook events (no valid signature). Config-driven per case — doesn't infer app logic on its own. HTTP-only.
- `src/security_toolkit/recon/infra_testing.py` -> Phase 4.8: wraps `testssl.sh` (TLS/cert) and `nikto` (general misconfig) via subprocess against base_url — at least one required. Also wraps `nuclei` (optional, broad CVE-template scan, `-jsonl` output) the same way. None of the three ships with this repo. See `docs/pentest-tools-howto.md` §2.3/§2.4/§8.1.
- `src/security_toolkit/legacy_whitebox/` -> NOT used under the current engagement — needs filesystem/DB/WP-CLI access. Kept for a possible future white-box engagement only. Never add new checks here unless the engagement model has explicitly changed.
- `src/security_toolkit/reporting/report.py` -> Builds a `Report` from `Finding`s and renders it to JSON/HTML strings. Pure, no I/O — reused by both `cloud_report.py` (the normal path) and the legacy local `write_report`.
- `src/security_toolkit/reporting/cloud_report.py` -> Uploads a rendered report to Cloudinary (never local disk) and indexes it in MongoDB via `report_index.py`. `upload_report_cli` is what every `scripts/run_*.py` calls.
- `scripts/` -> Thin CLI entrypoints (argparse) that wire config + checks + reporting together. `scripts/legacy_whitebox/` mirrors the package split above. `scripts/run_all_tests.py` sequences the other `run_*.py` scripts as subprocesses rather than reimplementing their logic.
- `config/scope.example.json` -> Template for the allowlist, with one example `auth` block per site type. Real `config/scope.json` is gitignored.
- `tests/` -> Mirrors `src/security_toolkit/` structure 1:1, including the `legacy_whitebox/` split.

## 🚧 Strict Rules & Guardrails ("What NOT to do")

- **Never** add a check to the normal workflow (`recon/`, `scripts/` outside `legacy_whitebox/`) that needs filesystem, DB, or server-shell access. That access does not exist under the current security/dev engagement — if a check needs it, it belongs in `legacy_whitebox/`, clearly marked, and should not be wired into any non-legacy script.
- **Never** add a check that acts on a target not resolved through `security_toolkit.config.load_authorized_target`. If a script doesn't call it, that's a bug.
- **Never** run anything in this repo against a live production site. Every script in here is meant for a staging/local copy per the playbook's safety rule — if you need a production exception, get a second person's sign-off and say so explicitly in the PR.
- **Never** hardcode credentials or API keys — read test-account credentials via `security_toolkit.config.load_test_credentials` (MongoDB), `load_credentials_from_env` (legacy `.env` fallback), or `load_db_config` (legacy only), never inline.
- **Never** point `MONGODB_URI` or `CLOUDINARY_URL` at a shared/production account — both are the toolkit's own private stores.
- **Never** write a report to local disk in the normal workflow — `cloud_report.upload_report_cli` is what every `run_*.py` script calls; `report.write_report` (local) is legacy/tests-only.
- **Never** have a check silently mutate or delete anything (files, DB rows, accounts). Account creation is the one explicit exception (provisioning the two disposable IDOR test accounts), and even that only through the site's own public signup flow, and only after the one confirmation prompt (or `--yes`).
- **Never** let any HTTP-based check call a URL that isn't validated through `security_toolkit.scope_guard.require_in_scope`/`resolve_in_scope_url` against the target's `base_url`.
- **Never** make `scripts/run_all_tests.py` (or any new orchestrator) ask a question mid-run — every possible prompt gets resolved via `orchestrator.plan_run` and asked (if at all) before any phase starts.
- **Never** commit `config/scope.json`, `.env`, or any of the per-target case-file directories (`config/idor_cases/`, etc.) — they're gitignored for a reason; don't force-add them.

## ⚙️ Custom Coding Standards & Workflows

- **Step 1 (Plan):** Before adding a new check, confirm which playbook phase/section it automates (see `docs/security-playbook.md`) and whether it can run purely over HTTP(S) — if not, it's `legacy_whitebox/` material, not the normal workflow.
- **Step 2 (TDD):** Write the test in `tests/` first for any pure-logic function (parsing, filtering, scoring). Only subprocess/DB/network calls get mocked rather than test-first — run `python -m pytest -q` before and after every change. Target 80%+ coverage (`--cov-report=term-missing` to see gaps).
- **Step 3 (Style):** Dataclasses are `frozen=True` (immutable results — never mutate a returned object, build a new one). Type-hint every function signature. Functions stay small and single-purpose; a new concern gets a new function, not a longer one. Validate all paths/inputs at the top of a function and fail fast with a clear exception.

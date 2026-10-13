# Security Toolkit

Automates the black-box side of our [security playbook](docs/security-playbook.md) —
external recon, auth/session checks, and IDOR testing — only against
sites we own or have explicit written authorization to test.

If you're new here, read this file top to bottom before running anything.
It's written so a new team member can get a report running without asking
anyone a question first.

## The engagement model (read this before anything else)

There's an agreement between our security team and dev team: **dev does
not share source code or server access with security.** We test as an
external black-box tester — HTTP(S) against the running app only — and
hand dev the findings at the end.

That means every check in this toolkit's normal workflow:
- never touches the app's filesystem or database,
- never shells into the app's server (no WP-CLI, no Artisan, no SSH),
- never reads source code, `package.json`, `.env`, or config files locally,
- only ever makes HTTP(S) requests the app's own server also sees from
  any other visitor.

A `legacy_whitebox/` package exists in this repo with older, white-box
checks (filesystem/DB/WP-CLI-based) — see **Legacy (white-box only)**
below for why it's kept and why you probably don't want to run it.

## What this is (and isn't)

- **Is:** read-only detection and reporting over HTTP. Every check lists
  what it found; nothing here deletes data, creates/escalates an account
  beyond the two disposable test accounts it's explicitly told to use, or
  changes anything on the target site.
- **Isn't:** a scanner you point at someone else's site. Every script
  refuses to run against anything not explicitly listed in
  `config/scope.json` — see **Authorization model** below.

## Authorization model

Every script resolves its target through `config/scope.json`, which is
**gitignored** — each person/environment keeps their own copy, scoped to
sites they're actually authorized to test. There is no way to point a
script at a URL that isn't listed there.

Add a target with `scripts/manage_scope.py` — no manual JSON editing:

```bash
python scripts/manage_scope.py add
```

It walks you through name, base URL, and (optionally) the login setup
for the IDOR/auth testers, interactively. For scripted/non-interactive
use, pass flags instead, e.g.:

```bash
python scripts/manage_scope.py add --name example-staging --base-url https://staging.example.com \
  --type laravel --auth-type form_session --login-url https://staging.example.com/login \
  --username-field email --csrf-page-url https://staging.example.com/login --csrf-field-name _token \
  --no-interactive
```

Other commands: `python scripts/manage_scope.py list` to see configured
targets, `python scripts/manage_scope.py remove --name <name>` to drop
one. Only list systems your team has signed-off access to test — a
staging clone, not production, per the playbook's safety rule.

If a script errors with "`X` is not in config/scope.json" — that's working
as intended. Add the target first with `manage_scope.py add`.

## Setup

Nothing persists locally except this repo and `.env` — reports go to
Cloudinary, test-account credentials go to MongoDB, scope config is the
only thing that's a local file (and it's gitignored). That's deliberate:
clone this repo on any machine, fill in `.env`, and you're back where
you left off, since the actual state lives in Mongo/Cloudinary, not on
disk. See `docs/RUNBOOK.md` for the bare command list; here's the same
thing explained:

```bash
git clone <this-repo>
cd security-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .          # makes `security_toolkit` importable by scripts/ and tests/

cp .env.example .env
# edit .env: MONGODB_URI (local or your own Atlas cluster) and
# CLOUDINARY_URL (from your Cloudinary dashboard's "API Environment variable")

python scripts/doctor.py
# checks everything's installed/configured and fixes what it can itself
# (pip packages, testssl.sh/nikto). Run this first on any new machine.
```

Then add your target — see **Authorization model** above — with
`scripts/manage_scope.py add`, and you're ready for **Running the
checks** below. Never commit `.env` or `config/scope.json`.

## Running everything at once (the normal way to use this)

```bash
python scripts/run_all_tests.py --target <name> \
  --register-url https://.../register \
  --protected-path /dashboard --logout-path /logout
```

This is the one command you'll run day-to-day per target. It figures
out everything up front — does this target already have test accounts?
which case files exist? — and asks its one possible question (permission
to create two real accounts on the live site, if none exist yet and you
gave a `--register-url`) immediately, before anything runs. Pass `--yes`
to skip that prompt for fully hands-off runs. After that it runs
straight through with no further prompts: account creation (if needed)
→ recon → auth/session → IDOR → injection → SSRF → upload →
business-logic → infra → a consolidated findings draft, skipping
whichever checks aren't set up yet and saying exactly why, then prints
one consolidated summary with every report's link. (The JWT tester isn't
included here — it needs a manually-captured token, so it stays a
separate command; see below.)

Drop `--register-url`/`--protected-path`/`--logout-path` if you don't
have them yet (invite-only site, or haven't found the right paths) —
it just skips those specific checks and runs everything else.

## Running checks individually

**Recon** (Phase 4.2 of the playbook — run this first on any new target,
to map the attack surface before anything else):

```bash
python scripts/run_recon.py --target example-staging
```

Checks: exposed sensitive files (`.git`, `.env`, backup/db dumps —
anything that shouldn't be publicly reachable), tech-stack fingerprinting
from response headers and cookie names, missing recommended security
headers, `xmlrpc.php` exposure (WordPress), and `robots.txt`/`sitemap.xml`
for unlinked paths worth investigating further. All GET requests against
the target's own public surface. Also runs two external-tool wrappers
automatically (skip with `--skip-subdomain-enum`/`--skip-dir-enum` if
either tool isn't installed, or the scan would take too long): subdomain
enumeration via `subfinder` (passive, public sources only — see
`docs/pentest-tools-howto.md` §8.2), and a wordlist-based directory/file
brute-force via `dirsearch` (§2.5) — a deeper, slower generalization of
the fixed exposed-files list above. `scripts/doctor.py` checks for both.

**Auth/session tester** (Phase 4.3 — needs the same `auth` block in
scope.json and `.env` test-account credentials as the IDOR tester below;
set those up first, then):

```bash
python scripts/run_auth_test.py --target example-staging \
  --protected-path /account/orders --logout-path /logout
```

Checks: session fixation (does the pre-login session cookie survive
login unchanged?), logout invalidation (does the session/token actually
stop working after logout, or just get discarded client-side?), and
login rate-limiting (does repeatedly retrying a wrong password with the
test account ever get throttled with an HTTP 429?). The rate-limit check
makes several real failed-login attempts against your own test account —
pass `--skip-rate-limit` to leave it out. Never tries to guess a real
account's password.

**IDOR tester** (Phase 4.4 — the two-account horizontal privilege test,
automated across a list of endpoints). Different sites log in differently
— WordPress, Laravel, and a custom Node/Express API all authenticate
differently — so this is config-driven instead of one hardcoded flow. Set
it up once per target:

1. **Set up MongoDB once** — the toolkit's own credential store (never
   the target app's DB). Point `MONGODB_URI` in `.env` at either a local
   instance (default `mongodb://localhost:27017`) or your own private
   Atlas cluster (`mongodb+srv://user:pass@cluster-host/...` — needs
   `dnspython`, already in `requirements.txt`). Never a shared/production
   cluster.

2. **Get two disposable test accounts** on staging (Phase 4.1 — User A
   and User B, each with some fake data of their own: an order, a
   profile, a message), stored keyed by target name so every site's test
   accounts coexist (no more overwriting one flat `.env` per target):
   - **If the site has open/public self-serve signup** (common on
     Laravel/Node apps, sometimes WordPress): fully automated —
     ```bash
     python scripts/provision_test_accounts.py --target example-staging --register-url https://staging-app.example.com/register
     ```
     It auto-detects the registration form (same approach as the login
     auto-detect below), creates both accounts, and saves their
     credentials into MongoDB for this target.
   - **If signup is invite-only or admin-created** (most apps): not
     automatable from outside the app, by definition of black-box. Ask
     the dev team for the two accounts' credentials (never code or
     server access), then store them:
     ```bash
     python scripts/manage_credentials.py add --target example-staging --label IDOR_USER_A
     python scripts/manage_credentials.py add --target example-staging --label IDOR_USER_B
     ```

3. **Add an `auth` block to that target** in `config/scope.json` — pick
   the adapter that matches the site (see
   `src/security_toolkit/recon/auth.py`'s docstring for the full schema,
   and `config/scope.example.json` for a filled-in example of each):
   - `"type": "wordpress"` — cookie session via `wp-login.php`.
   - `"type": "form_session"` — classic server-rendered login with an
     optional CSRF token (covers most Laravel apps).
   - `"type": "json_token"` — JSON API login returning a bearer token
     (covers most custom Node/Express APIs).
   - Something else entirely (SSO, MFA)? Write a one-off class with a
     `login(session, credentials)` method matching the same shape and
     pass it straight to `run_idor_suite` instead of `build_auth_provider`.
     Still HTTP-only — no code access needed, just knowledge of the flow
     a normal user goes through in a browser.

4. **List the endpoints to test**: copy `config/idor_cases.example.json`
   to e.g. `config/idor_cases/<target-name>.json` and fill in each
   endpoint plus an ID that belongs to User A — found through recon/manual
   browsing, not from reading the app's route definitions.

5. **Run it:**
   ```bash
   python scripts/run_idor_test.py --target example-staging --cases config/idor_cases/example-staging.json
   ```

It's GET-only by default and every URL is checked against the target's
`base_url` before any request goes out — it raises `OutOfScopeError`
rather than hitting anything else.

**Injection tester** (Phase 4.5 — SQLi/NoSQLi/XSS payload sweeps against
a named parameter). No account needed; copy
`config/injection_points.example.json` to
`config/injection_points/<target-name>.json`, list the parameters to
probe, then:

```bash
python scripts/run_injection_test.py --target example-staging --points config/injection_points/example-staging.json
```

Checks per parameter: a handful of SQL-breaking payloads checked against
known DB-error strings in the response; the same for NoSQL-operator
payloads (`$ne`, `$gt`, `$regex`) when the parameter sits in a JSON
body — also flags an unexpected 2xx on an operator payload, the shape
used for NoSQLi auth bypass; and a unique XSS marker checked for
unescaped reflection in the response body. **These are signals for a
human to confirm, not a final verdict** — especially a flagged SQLi
result, re-check manually (or with `sqlmap`/`NoSQLMap` — see
`docs/pentest-tools-howto.md` §3.1/§3.2 for install/usage — not yet
wrapped by this toolkit itself) before reporting it as a confirmed
finding. All payloads are
read-only in intent — nothing here tries to `DROP`/`UPDATE`/`DELETE`.
Also runs a command/template-injection sweep on the same parameter
(`{{7*7}}`, `${7*7}`, etc.) — flags if the evaluated result (`49`) shows
up instead of the literal payload. An automatic rate-limit check runs
per point too, same signal the auth tester uses for login.

**SSRF tester** (Phase 4.5 — out-of-band confirmation). Reuses the same
`config/injection_points/<target-name>.json` file — point it at anything
where the server fetches a URL on your behalf (webhooks, image proxy,
PDF export, link previews):

```bash
python scripts/run_ssrf_test.py --target example-staging --points config/injection_points/example-staging.json
```

Sends a fresh, disposable [webhook.site](https://webhook.site) callback
URL as the parameter's value, then polls that service for whether the
target's server actually made an outbound request to it. A flagged
result here is a **confirmed** SSRF — the server really did reach
out — not a guess from timing or response content. (webhook.site over
something like `interactsh`: same confirmed-hit outcome, but a plain
REST API instead of a Go binary/DNS-crypto protocol to get wrong.)

**JWT tester** (Phase 4.3 — `jwt_tool`-style tampering, no browser or
external binary). Capture a token from a browser's dev tools / Burp /
the `Authorization` header after logging in manually:

```bash
python scripts/run_jwt_test.py --target example-staging --token eyJ... --protected-path /account
```

Checks: missing `exp`/`iss`/`aud` claims; `alg: none` bypass (strip the
signature, resubmit); weak-secret HS256 brute force against a small
built-in wordlist (confirmed by cryptography alone, no server round-trip
needed); RS256→HS256 confusion if you pass `--public-key-file` (from a
JWKS endpoint found during recon). The **storage hint** — whether the
token is likely headed for localStorage — runs automatically as part of
`run_auth_test.py` instead, since that script already performs the login
and can read the raw `Set-Cookie` headers: a JWT-shaped cookie missing
`HttpOnly`, or a token returned only in the JSON body with no cookie at
all, both get flagged without needing a headless browser.

**Upload tester** (Phase 4.6 — extension bypass, content-type spoofing, a
GIF/PHP polyglot, and a path-traversal filename). Copy
`config/upload_cases.example.json` to
`config/upload_cases/<target-name>.json`, list the upload endpoints, then:

```bash
python scripts/run_upload_test.py --target example-staging --cases config/upload_cases/example-staging.json
```

Each payload carries a unique marker instead of doing anything with
execution. Two signals per upload: **accepted** (2xx despite the
filename/content-type looking like a script) and **executed** (fetching
the file back shows the marker rendered as output, not the raw `<?php`
source sitting there unexecuted) — the second one is what actually
matters. Confirming execution needs a URL for the uploaded file: set
`response_url_json_path` if the app returns it in the response, or
`uploaded_file_url_template` if upload URLs follow a predictable
pattern. Without either, an accepted upload is flagged for manual review
since execution can't be confirmed either way.

**Business-logic tester** (Phase 4.7 — the category scanners can't find,
since it needs knowing what the app's *correct* behavior should be, not
just what a payload triggers). Copy
`config/business_logic_cases.example.json` to
`config/business_logic_cases/<target-name>.json` — each case has to be
learned from using the app normally first (a real checkout flow, a real
coupon's stated limit, a real webhook payload shape), then:

```bash
python scripts/run_business_logic_test.py --target example-staging --cases config/business_logic_cases/example-staging.json
```

Four checks, each independently configured:
- **price/quantity tampering** — send a client-controlled price the
  server should recompute itself, flag if it's accepted.
- **coupon/discount reuse** — apply the same code more times than its
  stated limit, flag if more than that many succeed.
- **rate-limited one-time actions** — hit a referral/OTP/free-trial
  endpoint repeatedly, flag if nothing throttles it with an HTTP 429.
- **forged webhook events** — POST a fabricated event (the Stripe
  `payment_intent.succeeded`-with-no-signature scenario the playbook
  names specifically) with a bogus or missing signature header, flag if
  it's accepted as real.

**Infra tester** (Phase 4.8 — TLS/cert misconfiguration and general
server misconfiguration). Wraps two external tools the playbook already
names rather than reimplementing them — install them separately first:

```bash
brew install testssl nikto   # or your platform's equivalent
python scripts/run_infra_test.py --target example-staging
```

`testssl.sh` checks TLS/certificate config and flags
HIGH/CRITICAL/VULNERABLE markers in its own output; `nikto` scans for
general server misconfiguration and outdated software, flagged if it
reports any findings. Both run entirely over the network against the
target's `base_url`. Use `--skip-testssl`/`--skip-nikto` to run just one.
Install/usage details for both (and every other external tool this
toolkit wraps or references) are in `docs/pentest-tools-howto.md`.

Every report uploads straight to Cloudinary as JSON + HTML — nothing is
written to local disk, ever, so there's no `reports/` folder to worry
about leaving sensitive findings in on whatever machine you're using.
Each upload is also indexed in MongoDB (target, title, timestamp, both
URLs, whether it was flagged, and the full findings list) — see
`report_index.py` — so the planned dashboard can list every report from
every machine with one query, and so the findings draft below doesn't
need to re-fetch anything from Cloudinary.

**Generating a findings draft** (Phase 4.10 — "document every finding").
Run this once you've run whatever scans you want included:

```bash
python scripts/generate_findings_report.py --target example-staging
python scripts/generate_findings_report.py --target example-staging --upload  # also puts a copy on Cloudinary
```

Pulls every flagged finding on record for the target from MongoDB and
writes one consolidated Markdown draft, grouped by scan type, with the
reproduction detail each check already captured and blank Impact/Fix
fields. This automates the *aggregation* only — read the whole draft
once, fill in impact/fix/priority, and only then is it ready to send to
the dev team; nothing here sends it anywhere on its own.

Share the links with the dev team at the end of the engagement, per the
deal, rather than piecemeal.

## Legacy (white-box only — not used under the current engagement)

`src/security_toolkit/legacy_whitebox/` and `scripts/legacy_whitebox/`
hold older checks (Phase 1 incident triage, the monthly hardening
checklist) that need a filesystem path on the app's server, direct DB
credentials, or WP-CLI/Artisan on a shell — access the security team does
not have under the current dev/security agreement. They're kept, not
deleted, in case a future engagement is ever explicitly scoped as
white-box/internal with the dev team's sign-off. Running anything there
prints a loud warning; don't use it under the current deal.

## Project structure

```
security-toolkit/
├── CLAUDE.md                        # Context/instructions for Claude Code — read alongside this file
├── README.md                        # This file
├── docs/
│   ├── security-playbook.md         # The source playbook every check here automates a piece of
│   ├── pentest-tools-howto.md       # Install/run guide for every external tool the playbook names (companion doc)
│   └── RUNBOOK.md                   # Just the commands, in order — no explanations
├── config/
│   ├── scope.example.json           # Template for config/scope.json (gitignored) — or just use manage_scope.py
│   ├── scope.json                   # (gitignored) your real authorized-target list
│   ├── idor_cases.example.json      # Template — copy per target, list endpoints to IDOR-test
│   ├── injection_points.example.json # Template — copy per target, list parameters to probe
│   ├── upload_cases.example.json     # Template — copy per target, list upload endpoints to probe
│   └── business_logic_cases.example.json # Template — copy per target, list price/coupon/webhook cases
├── .env.example                     # Template — copy to .env (gitignored): MONGODB_URI, CLOUDINARY_URL, legacy fallbacks
├── vendor/                           # (gitignored) testssl.sh/nikto, if doctor.py cloned them here
├── src/security_toolkit/
│   ├── config.py                    # Authorization gate + env loading — every check goes through this
│   ├── scope_guard.py                # Shared "never request outside base_url" check
│   ├── scope_manager.py              # Add/list/remove-target logic behind scripts/manage_scope.py
│   ├── credentials_db.py             # MongoDB-backed test-account credential store, keyed by target+label
│   ├── report_index.py               # MongoDB index of every report ever uploaded — for the planned dashboard
│   ├── doctor_checks.py              # Pure logic behind scripts/doctor.py (OS/package-manager detection, checks)
│   ├── tool_locations.py             # Resolves testssl.sh/nikto/dirsearch/subfinder: PATH first, then a vendor/ fallback (subfinder: PATH only)
│   ├── orchestrator.py               # Pure "what to run/skip and why" logic behind scripts/run_all_tests.py
│   ├── findings_report.py            # Phase 4.10: aggregates flagged findings into one consolidated Markdown draft
│   ├── env_file.py                   # Merge-in-place .env updates (legacy credential path only)
│   ├── recon/                        # Black-box modules — HTTP(S) only, the normal workflow
│   │   ├── fingerprint.py            # Phase 4.2: recon — exposed files, tech fingerprint, xmlrpc, robots.txt
│   │   ├── subdomain_enum.py         # Phase 4.2: wraps subfinder (passive subdomain discovery), wired into run_recon.py
│   │   ├── dir_enum.py               # Phase 4.2: wraps dirsearch (wordlist-based path brute-force), wired into run_recon.py
│   │   ├── html_forms.py             # Shared HTML <form> parsing for login/register auto-detection
│   │   ├── auth.py                   # Pluggable login adapters (WordPress/Laravel/JSON-token/custom)
│   │   ├── auth_detect.py            # Auto-detects a login form's fields -> an `auth` block
│   │   ├── provision.py              # Creates IDOR test accounts via a site's own public signup (auto-detected form or JSON API)
│   │   ├── rate_limit_check.py       # Shared rate-limit probe, wired automatically into IDOR/injection/upload
│   │   ├── session_testing.py        # Phase 4.3: session fixation, logout invalidation, login rate-limiting
│   │   ├── jwt_testing.py            # Phase 4.3: JWT tampering (claims, alg=none, weak secret, RS256->HS256, storage hint)
│   │   ├── idor_tester.py            # Phase 4.4: two-account IDOR testing + sequential-ID enumeration
│   │   ├── injection_testing.py      # Phase 4.5: SQLi/NoSQLi/XSS/template-injection payload sweeps
│   │   ├── ssrf_testing.py           # Phase 4.5: SSRF via webhook.site out-of-band callback confirmation
│   │   ├── upload_testing.py         # Phase 4.6: file-upload testing (extension/content-type/polyglot)
│   │   ├── business_logic_testing.py # Phase 4.7: price tamper, coupon reuse, rate limiting, forged webhooks
│   │   └── infra_testing.py          # Phase 4.8: wraps testssl.sh + nikto
│   ├── legacy_whitebox/              # NOT used currently — needs server/DB/code access, see above
│   │   ├── incident_triage.py
│   │   ├── monthly_checklist.py
│   │   └── provision.py
│   └── reporting/
│       ├── report.py                 # Build a Report + render it to JSON/HTML strings (pure, no I/O)
│       └── cloud_report.py           # Uploads a rendered report to Cloudinary + indexes it in MongoDB
├── scripts/
│   ├── doctor.py                      # Checks + auto-fixes this machine's setup — run first, any machine
│   ├── manage_scope.py                # Add/list/remove targets in scope.json — no manual JSON editing
│   ├── provision_test_accounts.py    # Auto-creates the two IDOR/auth test accounts, saves creds to MongoDB
│   ├── manage_credentials.py         # Add/list/remove test-account credentials in MongoDB by hand
│   ├── run_all_tests.py              # Runs every check for one target in a single command — the normal way to use this
│   ├── run_recon.py                  # CLI entrypoint (black-box)
│   ├── run_auth_test.py              # CLI entrypoint (black-box)
│   ├── run_idor_test.py              # CLI entrypoint (black-box)
│   ├── run_injection_test.py         # CLI entrypoint (black-box)
│   ├── run_upload_test.py            # CLI entrypoint (black-box)
│   ├── run_business_logic_test.py    # CLI entrypoint (black-box)
│   ├── run_ssrf_test.py              # CLI entrypoint (black-box)
│   ├── run_jwt_test.py               # CLI entrypoint (black-box, needs a captured token)
│   ├── run_infra_test.py             # CLI entrypoint (black-box)
│   ├── generate_findings_report.py   # Aggregates flagged findings into one consolidated draft
│   └── legacy_whitebox/              # NOT used currently, see above
└── tests/                            # Mirrors src/security_toolkit/ structure, one test file per module
```

## Testing

```bash
python -m pytest -q
python -m pytest --cov=security_toolkit --cov-report=term-missing   # check coverage gaps
```

Tests don't need a real WordPress install, database, or live site —
subprocess/network calls are mocked. Run them before and after any change.

## Adding a new check

1. Find the playbook phase/section it automates in `docs/security-playbook.md`.
2. Ask: can this run purely over HTTP(S) against the live app? If it
   needs filesystem, DB, or server-shell access, it belongs in
   `legacy_whitebox/`, not the normal workflow — see **The engagement
   model** above.
3. Add the function to the right module under `src/security_toolkit/recon/`
   (or a new module if it's a new category) — detection/reporting only,
   no mutation, and resolve its target via `load_authorized_target`, with
   every URL going through `scope_guard`.
4. Write the test first for any pure-logic piece (parsing, filtering,
   scoring) in the matching `tests/` file.
5. Wire it into the relevant `scripts/run_*.py`, or add a new script if
   it's its own recurring job.
6. Run `python -m pytest -q` and confirm coverage didn't regress.

See `CLAUDE.md` for the full guardrails (what never to automate, immutability conventions, etc.) before opening a PR.

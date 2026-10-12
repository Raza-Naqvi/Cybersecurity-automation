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

```bash
git clone <this-repo>
cd security-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .          # makes `security_toolkit` importable by scripts/ and tests/

cp config/scope.example.json config/scope.json   # then edit it — see above
cp .env.example .env                              # then fill in real test-account creds
```

Never commit `.env` or `scope.json`.

## Running the checks

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
the target's own public surface.

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

1. **Get two disposable test accounts** on staging (Phase 4.1 — User A
   and User B, each with some fake data of their own: an order, a
   profile, a message):
   - **If the site has open/public self-serve signup** (common on
     Laravel/Node apps, sometimes WordPress): automatable —
     ```python
     from security_toolkit.recon.provision import register_via_api
     register_via_api("https://staging-app.example.com/register", {"email": "idor-a@test.local", "password": "...", "name": "IDOR User A"})
     ```
   - **If signup is invite-only or admin-created** (most apps): not
     automatable from outside the app, by definition of black-box. Ask
     the dev team to create the two accounts for you — without sharing
     any code or server access back, just the two sets of credentials —
     then move on to step 2.

2. **Store their credentials in `.env`** — never in `scope.json`, never in
   code:
   ```
   IDOR_USER_A_USERNAME=idor_user_a
   IDOR_USER_A_PASSWORD=...
   IDOR_USER_B_USERNAME=idor_user_b
   IDOR_USER_B_PASSWORD=...
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
result, re-check manually (or with `sqlmap`, per the playbook's tool
list) before reporting it as a confirmed finding. All payloads are
read-only in intent — nothing here tries to `DROP`/`UPDATE`/`DELETE`.

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

Reports from every CLI script land in `reports/` as both `.json` and
`.html` (gitignored — they can contain sensitive findings; share them
with the dev team at the end of the engagement, per the deal, rather than
piecemeal).

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
├── docs/security-playbook.md        # The source playbook every check here automates a piece of
├── config/
│   ├── scope.example.json           # Template — copy to scope.json (gitignored) and fill in
│   ├── scope.json                   # (gitignored) your real authorized-target list
│   ├── idor_cases.example.json      # Template — copy per target, list endpoints to IDOR-test
│   ├── injection_points.example.json # Template — copy per target, list parameters to probe
│   ├── upload_cases.example.json     # Template — copy per target, list upload endpoints to probe
│   └── business_logic_cases.example.json # Template — copy per target, list price/coupon/webhook cases
├── .env.example                     # Template — copy to .env (gitignored) for test-account creds
├── src/security_toolkit/
│   ├── config.py                    # Authorization gate + env loading — every check goes through this
│   ├── scope_guard.py                # Shared "never request outside base_url" check
│   ├── scope_manager.py              # Add/list/remove-target logic behind scripts/manage_scope.py
│   ├── recon/                        # Black-box modules — HTTP(S) only, the normal workflow
│   │   ├── fingerprint.py            # Phase 4.2: recon — exposed files, tech fingerprint, xmlrpc, robots.txt
│   │   ├── auth.py                   # Pluggable login adapters (WordPress/Laravel/JSON-token/custom)
│   │   ├── provision.py              # Creates IDOR test accounts via a site's own public signup
│   │   ├── session_testing.py        # Phase 4.3: session fixation, logout invalidation, login rate-limiting
│   │   ├── idor_tester.py            # Phase 4.4: two-account IDOR testing
│   │   ├── injection_testing.py      # Phase 4.5: SQLi/NoSQLi/XSS payload sweeps
│   │   ├── upload_testing.py         # Phase 4.6: file-upload testing (extension/content-type/polyglot)
│   │   ├── business_logic_testing.py # Phase 4.7: price tamper, coupon reuse, rate limiting, forged webhooks
│   │   └── infra_testing.py          # Phase 4.8: wraps testssl.sh + nikto
│   ├── legacy_whitebox/              # NOT used currently — needs server/DB/code access, see above
│   │   ├── incident_triage.py
│   │   ├── monthly_checklist.py
│   │   └── provision.py
│   └── reporting/
│       └── report.py                 # Findings -> JSON + HTML report
├── scripts/
│   ├── manage_scope.py                # Add/list/remove targets in scope.json — no manual JSON editing
│   ├── run_recon.py                  # CLI entrypoint (black-box)
│   ├── run_auth_test.py              # CLI entrypoint (black-box)
│   ├── run_idor_test.py              # CLI entrypoint (black-box)
│   ├── run_injection_test.py         # CLI entrypoint (black-box)
│   ├── run_upload_test.py            # CLI entrypoint (black-box)
│   ├── run_business_logic_test.py    # CLI entrypoint (black-box)
│   ├── run_infra_test.py             # CLI entrypoint (black-box)
│   └── legacy_whitebox/              # NOT used currently, see above
├── reports/                          # (gitignored output) generated reports land here
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

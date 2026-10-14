# Runbook

Just the commands, in order. See `README.md` for explanations.

## Once per machine

```bash
git clone <this-repo>
cd security-toolkit
python3 -m venv .venv
source .venv/bin/activate

cp .env.example .env
# edit .env: paste in your MONGODB_URI (local or your own Atlas cluster)
#            and CLOUDINARY_URL (from your Cloudinary dashboard)

python scripts/doctor.py
# fixes what it can (pip packages, testssl.sh/nikto) and tells you how
# to fix anything it can't (Mongo/Cloudinary credentials)
```

## Once per target site

```bash
python scripts/manage_scope.py add
# interactive — name, base URL, and (pick "auto") the login page URL;
# it detects the rest. Or pass flags for non-interactive use, see README.
```

## Every time you test that target

```bash
python scripts/run_all_tests.py --target <name> \
  --register-url https://.../register \
  --protected-path /dashboard \
  --logout-path /logout
```

That single command:
- creates the two test accounts automatically if none exist yet for this target (asks once, up front, before doing anything, unless `--yes` is passed)
- runs recon, auth/session, IDOR, injection, upload, business-logic, and infra checks — skipping whichever aren't set up yet, and saying why
- uploads every report to Cloudinary and prints every link in one summary at the end

If you don't have a register URL (invite-only site) or don't want auth/IDOR run yet, drop `--register-url`/`--protected-path`/`--logout-path` — it just skips those and runs everything else.

## Individual checks (if you want to run just one)

```bash
python scripts/run_recon.py --target <name>
python scripts/run_auth_test.py --target <name> --protected-path <path> --logout-path <path>
python scripts/run_idor_test.py --target <name> --cases config/idor_cases/<name>.json
python scripts/run_injection_test.py --target <name> --points config/injection_points/<name>.json
python scripts/run_upload_test.py --target <name> --cases config/upload_cases/<name>.json
python scripts/run_business_logic_test.py --target <name> --cases config/business_logic_cases/<name>.json
python scripts/run_ssrf_test.py --target <name> --points config/injection_points/<name>.json
python scripts/run_jwt_test.py --target <name> --token <captured-jwt> --protected-path <path>
python scripts/run_infra_test.py --target <name>
python scripts/run_wp_test.py --target <name>
# ^ WordPress enumeration + vulnerability matching (our own WPScan
#   alternative) - only meaningful for a target with "type": "wordpress"
#   in scope.json; also runs automatically inside run_recon.py for such
#   targets. Vulnerability matching needs a free WORDFENCE_API_KEY in
#   .env - pass --skip-vuln-match to run enumeration only.

python scripts/generate_findings_report.py --target <name>
# aggregates every flagged finding on record for this target into one draft
```

## Managing test-account credentials by hand (invite-only sites)

```bash
python scripts/manage_credentials.py add --target <name> --label IDOR_USER_A
python scripts/manage_credentials.py add --target <name> --label IDOR_USER_B
python scripts/manage_credentials.py list --target <name>
python scripts/manage_credentials.py remove --target <name> --label IDOR_USER_A
```

## Tests (if you're changing the toolkit itself)

```bash
python -m pytest -q
python -m pytest --cov=security_toolkit --cov-report=term-missing
```

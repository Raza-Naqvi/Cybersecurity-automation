#!/usr/bin/env python3
"""CLI: Phase 4.2 black-box recon report for an authorized target.

Pure HTTP(S) — no filesystem, DB, or server access needed. Safe to run
against any staging target with just its base_url set in scope.json.

Usage:
    python scripts/run_recon.py --target example-staging
"""

from __future__ import annotations

import argparse
import os
import sys

from security_toolkit.config import load_authorized_target_cli, load_env
from security_toolkit.recon import fingerprint
from security_toolkit.recon.dir_enum import DEFAULT_EXTENSIONS, run_dirsearch
from security_toolkit.recon.safe_browsing_check import check_safe_browsing
from security_toolkit.recon.subdomain_enum import run_subfinder
from security_toolkit.recon.wp_enum import run_wp_enum
from security_toolkit.recon.wp_vuln_match import run_wp_vuln_match
from security_toolkit.reporting.cloud_report import upload_report_cli
from security_toolkit.reporting.report import Finding, build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="Target name from config/scope.json")
    parser.add_argument(
        "--skip-subdomain-enum", action="store_true", help="Skip the subfinder subdomain-enumeration check"
    )
    parser.add_argument(
        "--skip-dir-enum", action="store_true", help="Skip the dirsearch directory/file brute-force check"
    )
    parser.add_argument(
        "--dir-enum-extensions", default=DEFAULT_EXTENSIONS, help=f"Extensions for dirsearch (default: {DEFAULT_EXTENSIONS})"
    )
    parser.add_argument(
        "--skip-safe-browsing", action="store_true", help="Skip the Google Safe Browsing blacklist check"
    )
    parser.add_argument(
        "--skip-wp-enum", action="store_true", help="Skip WordPress enumeration (only runs when target.type == 'wordpress')"
    )
    parser.add_argument(
        "--skip-vuln-match", action="store_true",
        help="Skip matching detected WordPress versions against the Wordfence Intelligence vulnerability feed",
    )
    args = parser.parse_args()

    target = load_authorized_target_cli(args.target)
    if target is None:
        return 1

    if not target.base_url:
        print(f"ERROR: target '{target.name}' has no base_url in scope.json", file=sys.stderr)
        return 1

    findings = []

    exposed = fingerprint.check_exposed_files(target)
    flagged_files = [item for item in exposed if item.flagged]
    findings.append(
        Finding(
            name="Exposed sensitive files",
            flagged=len(flagged_files) > 0,
            detail="\n".join(f"{item.path} :: {item.detail}" for item in flagged_files) or "none reachable",
        )
    )

    headers = fingerprint.fingerprint_headers(target)
    findings.append(
        Finding(
            name="Tech fingerprint (headers + cookies)",
            flagged=False,
            detail=(
                f"headers: {headers.tech_headers or 'none revealed'}\n"
                f"cookie hints: {', '.join(headers.cookie_hints) or 'none'}"
            ),
        )
    )
    findings.append(
        Finding(
            name="Missing recommended security headers",
            flagged=len(headers.missing_security_headers) > 0,
            detail=", ".join(headers.missing_security_headers) or "all present",
        )
    )

    xmlrpc = fingerprint.check_xmlrpc(target)
    findings.append(
        Finding(name="xmlrpc.php exposure", flagged=bool(xmlrpc.risky_methods_exposed), detail=xmlrpc.detail)
    )

    robots = fingerprint.check_robots_and_sitemap(target)
    findings.append(
        Finding(
            name="robots.txt / sitemap.xml",
            flagged=False,
            detail=(
                f"sitemap present: {robots['sitemap_present']}\n"
                f"disallowed paths worth investigating: {', '.join(robots['disallowed_paths']) or 'none listed'}"
            ),
        )
    )

    if not args.skip_subdomain_enum:
        subdomains = run_subfinder(target)
        findings.append(Finding(name="Subdomain enumeration (subfinder)", flagged=subdomains.flagged, detail=subdomains.detail))

    if not args.skip_dir_enum:
        dirs = run_dirsearch(target, extensions=args.dir_enum_extensions)
        findings.append(Finding(name="Directory/file brute-force (dirsearch)", flagged=dirs.flagged, detail=dirs.detail))

    if not args.skip_safe_browsing:
        if not os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"):
            load_env()  # .env isn't loaded automatically anywhere else in the process
        safe_browsing = check_safe_browsing(target, api_key=os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"))
        findings.append(
            Finding(name="Malware/phishing blacklist (Google Safe Browsing)", flagged=safe_browsing.flagged, detail=safe_browsing.detail)
        )

    if not args.skip_wp_enum and target.type == "wordpress":
        wp_result = run_wp_enum(target)
        findings.append(Finding(name="WordPress detection/enumeration", flagged=False, detail=wp_result.detail))
        if wp_result.is_wordpress:
            findings.append(
                Finding(
                    name="WordPress username enumeration",
                    flagged=len(wp_result.usernames) > 0,
                    detail=(f"FLAGGED: {', '.join(wp_result.usernames)}" if wp_result.usernames else "no usernames exposed"),
                )
            )
            if not args.skip_vuln_match:
                if not os.environ.get("WORDFENCE_API_KEY"):
                    load_env()
                vuln_result = run_wp_vuln_match(wp_result, api_key=os.environ.get("WORDFENCE_API_KEY"))
                findings.append(
                    Finding(name="WordPress vulnerability matching (Wordfence Intelligence)", flagged=vuln_result.flagged, detail=vuln_result.detail)
                )

    report = build_report(title="Recon", target=target.name, findings=findings)
    if upload_report_cli(report) is None:
        return 1
    return 2 if report.has_flags else 0


if __name__ == "__main__":
    raise SystemExit(main())

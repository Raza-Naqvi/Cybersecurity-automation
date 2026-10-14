#!/usr/bin/env python3
"""CLI: checks whether this machine is ready to run the security
toolkit, and fixes what it can itself (installs missing pip packages;
installs testssl.sh/nikto via your OS package manager or, failing that,
a git clone into vendor/). Run this first on any new machine.

At least one of testssl.sh/nikto is required (not fully skippable) — the
infra tests run with whichever ends up available if only one installs.

Usage:
    python scripts/doctor.py              # checks AND fixes what it can
    python scripts/doctor.py --check-only  # just reports, changes nothing
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from security_toolkit.config import REPO_ROOT
from security_toolkit.doctor_checks import (
    REQUIRED_PACKAGES,
    CheckResult,
    build_git_clone_command,
    build_package_manager_install_command,
    check_cloudinary_env_keys,
    check_env_file,
    check_package_importable,
    check_python_version,
    check_safe_browsing_env_key,
    check_tool_on_path,
    check_wordfence_env_key,
    detect_os,
    detect_package_manager,
)
from security_toolkit.tool_locations import (
    VENDOR_DIR,
    VENDORED_DIRSEARCH_PATH,
    VENDORED_NIKTO_PATH,
    VENDORED_TESTSSL_PATH,
)

ENV_PATH = REPO_ROOT / ".env"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"
REQUIREMENTS_PATH = REPO_ROOT / "requirements.txt"


def _print_result(result: CheckResult) -> None:
    mark = "✅" if result.passed else "❌"
    print(f"{mark} {result.name}: {result.detail}")
    if not result.passed and result.fix_hint:
        print(f"   fix: {result.fix_hint}")


def _run_live(cmd: list[str], **kwargs) -> int:
    """Run a command with the terminal's own stdio (so sudo password
    prompts and install progress show up normally), returning its exit
    code. Never raises on a missing command — that's just another
    failed attempt to report.
    """
    try:
        return subprocess.run(cmd, **kwargs).returncode
    except FileNotFoundError:
        return 127


def ensure_pip_packages(check_only: bool) -> CheckResult:
    missing = [
        (import_name, pip_name)
        for import_name, pip_name in REQUIRED_PACKAGES
        if not check_package_importable(import_name, pip_name).passed
    ]
    if not missing:
        return CheckResult(name="pip packages", passed=True, detail="all installed")

    names = ", ".join(pip_name for _, pip_name in missing)
    if check_only:
        return CheckResult(
            name="pip packages", passed=False, detail=f"missing: {names}",
            fix_hint=f"pip install -r {REQUIREMENTS_PATH}",
        )

    print(f"Installing missing packages ({names})...")
    _run_live([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS_PATH)])

    still_missing = [pip_name for import_name, pip_name in missing if not check_package_importable(import_name, pip_name).passed]
    if still_missing:
        return CheckResult(
            name="pip packages", passed=False, detail=f"still missing after install attempt: {', '.join(still_missing)}",
            fix_hint=f"pip install -r {REQUIREMENTS_PATH}",
        )
    return CheckResult(name="pip packages", passed=True, detail="installed")


def ensure_env_file(check_only: bool) -> CheckResult:
    if not ENV_PATH.exists() and not check_only and ENV_EXAMPLE_PATH.exists():
        shutil.copy(ENV_EXAMPLE_PATH, ENV_PATH)
        print(f"Created {ENV_PATH} from .env.example — fill in MONGODB_URI and Cloudinary config.")
    return check_env_file(ENV_PATH)


def check_mongo_ping() -> CheckResult:
    try:
        import os

        from dotenv import load_dotenv

        load_dotenv(ENV_PATH)
        uri = os.environ.get("MONGODB_URI")
        if not uri:
            return CheckResult(name="MongoDB connection", passed=False, detail="MONGODB_URI not set")
        from pymongo import MongoClient

        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        return CheckResult(name="MongoDB connection", passed=True, detail="connected")
    except Exception as exc:  # noqa: BLE001 — any failure here is just "can't connect", not a crash
        return CheckResult(
            name="MongoDB connection", passed=False, detail=str(exc)[:200],
            fix_hint="Check MONGODB_URI in .env (and that the cluster/user allows this connection).",
        )


def check_cloudinary_ping() -> CheckResult:
    try:
        import os

        from dotenv import load_dotenv

        load_dotenv(ENV_PATH)
        env_result = check_cloudinary_env_keys({k: v for k, v in os.environ.items() if k.startswith("CLOUDINARY_")})
        if not env_result.passed:
            return CheckResult(name="Cloudinary connection", passed=False, detail="not configured", fix_hint=env_result.fix_hint)

        import cloudinary
        import cloudinary.api

        # cloudinary's Config only auto-reads env vars once, at `cloudinary`'s
        # first import in the process — which already happened earlier in
        # ensure_pip_packages(), before .env was loaded. reset_config() forces
        # a fresh re-read of os.environ right now.
        cloudinary.reset_config()
        cloudinary.api.ping()
        return CheckResult(name="Cloudinary connection", passed=True, detail="connected")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="Cloudinary connection", passed=False, detail=str(exc)[:200],
            fix_hint="Check your Cloudinary credentials in .env.",
        )


def _tool_present(path_on_path: str | None, vendored_path: Path) -> bool:
    return bool(path_on_path) or vendored_path.exists()


def ensure_infra_tool(
    display_name: str,
    which_name: str,
    vendored_path: Path,
    clone_dest: Path,
    package_name: str,
    git_url: str,
    check_only: bool,
    extra_runtime: str | None = None,
) -> CheckResult:
    on_path = shutil.which(which_name)
    if _tool_present(on_path, vendored_path):
        return CheckResult(name=display_name, passed=True, detail=on_path or str(vendored_path))

    if check_only:
        return CheckResult(
            name=display_name, passed=False, detail="not found",
            fix_hint=f"Install via your package manager, or: git clone {git_url} {clone_dest}",
        )

    os_name = detect_os()
    package_manager = detect_package_manager(os_name)
    if package_manager:
        cmd = build_package_manager_install_command(package_manager, package_name)
        if cmd:
            print(f"Installing {display_name} via {package_manager}...")
            _run_live(cmd)
            on_path = shutil.which(which_name)
            if on_path:
                return CheckResult(name=display_name, passed=True, detail=on_path)

    if extra_runtime and not shutil.which(extra_runtime):
        return CheckResult(
            name=display_name, passed=False,
            detail=f"package manager install didn't work and {extra_runtime} isn't available to run a vendored copy",
            fix_hint=f"Install {extra_runtime} yourself, then re-run this script.",
        )

    if shutil.which("git"):
        VENDOR_DIR.mkdir(parents=True, exist_ok=True)
        print(f"Cloning {display_name} into {clone_dest}...")
        _run_live(build_git_clone_command(git_url, clone_dest))
        if vendored_path.exists():
            if vendored_path.suffix != ".pl":
                vendored_path.chmod(0o755)
            return CheckResult(name=display_name, passed=True, detail=str(vendored_path))

    return CheckResult(
        name=display_name, passed=False, detail="could not install automatically",
        fix_hint=f"Install {display_name} manually, or: git clone {git_url} {clone_dest}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true", help="Report only, never install/change anything")
    args = parser.parse_args()

    print(f"OS: {detect_os()} | package manager: {detect_package_manager() or 'none found'}\n")

    results = [check_python_version()]
    results.append(ensure_pip_packages(args.check_only))
    results.append(ensure_env_file(args.check_only))
    results.append(check_mongo_ping())
    results.append(check_cloudinary_ping())

    testssl_result = ensure_infra_tool(
        display_name="testssl.sh",
        which_name="testssl.sh",
        vendored_path=VENDORED_TESTSSL_PATH,
        clone_dest=VENDOR_DIR / "testssl.sh",
        package_name="testssl",
        git_url="https://github.com/drwetter/testssl.sh.git",
        check_only=args.check_only,
    )
    nikto_result = ensure_infra_tool(
        display_name="nikto",
        which_name="nikto",
        vendored_path=VENDORED_NIKTO_PATH,
        clone_dest=VENDOR_DIR / "nikto",
        package_name="nikto",
        git_url="https://github.com/sullo/nikto.git",
        check_only=args.check_only,
        extra_runtime="perl",
    )
    results.extend([testssl_result, nikto_result])

    # Optional recon/infra enhancements (recon/subdomain_enum.py,
    # recon/dir_enum.py, infra_testing.run_nuclei) — none is required:
    # run_recon.py/run_infra_test.py already report "tool not found" per
    # check gracefully rather than failing the whole script, so these
    # never block "this machine is ready" the way testssl/nikto do.
    subfinder_result = check_tool_on_path(
        display_name="subfinder",
        which_name="subfinder",
        fix_hint="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest, "
        "or download a prebuilt binary — see docs/pentest-tools-howto.md §8.2",
    )
    dirsearch_result = ensure_infra_tool(
        display_name="dirsearch",
        which_name="dirsearch",
        vendored_path=VENDORED_DIRSEARCH_PATH,
        clone_dest=VENDOR_DIR / "dirsearch",
        package_name="dirsearch",
        git_url="https://github.com/maurosoria/dirsearch.git",
        check_only=args.check_only,
        extra_runtime="python3",
    )
    nuclei_result = check_tool_on_path(
        display_name="nuclei",
        which_name="nuclei",
        fix_hint="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest, "
        "or download a prebuilt binary — see docs/pentest-tools-howto.md §2.3. "
        "Run 'nuclei -update-templates' once after installing.",
    )

    import os

    from dotenv import load_dotenv

    load_dotenv(ENV_PATH)
    safe_browsing_result = check_safe_browsing_env_key(
        {k: v for k, v in os.environ.items() if k.startswith("GOOGLE_SAFE_BROWSING_")}
    )
    wordfence_result = check_wordfence_env_key(
        {k: v for k, v in os.environ.items() if k.startswith("WORDFENCE_")}
    )

    optional_results = [subfinder_result, dirsearch_result, nuclei_result, safe_browsing_result, wordfence_result]
    results.extend(optional_results)

    print()
    for result in results:
        _print_result(result)

    infra_ok = testssl_result.passed or nikto_result.passed
    print()
    if not infra_ok:
        print("❌ Neither testssl.sh nor nikto is available — infra checks need at least one.")
    for optional in optional_results:
        if not optional.passed:
            print(f"ℹ️  {optional.name} not available — the check it's used in still runs, just reports it as unavailable.")

    core_results = [r for r in results if r not in (testssl_result, nikto_result, *optional_results)]
    all_core_ok = all(r.passed for r in core_results)

    if all_core_ok and infra_ok:
        print("✅ This machine is ready.")
        return 0

    print("❌ Not ready yet — see the fix hints above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

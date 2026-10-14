"""Pure logic behind `scripts/doctor.py`: OS/package-manager detection,
individual check results, and the install commands it would run — all
testable without actually installing anything, hitting the network, or
touching the filesystem beyond what's passed in.

`scripts/doctor.py` is the thin CLI that actually runs these commands
and does the live pings (Mongo, Cloudinary) — consistent with the rest
of this toolkit (logic in `src/`, thin wiring in `scripts/`).
"""

from __future__ import annotations

import importlib
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

MIN_PYTHON = (3, 11)

# (import name, pip/display name) — what scripts/doctor.py checks for.
REQUIRED_PACKAGES = (
    ("requests", "requests"),
    ("pymongo", "pymongo"),
    ("dns", "dnspython"),
    ("jinja2", "Jinja2"),
    ("dotenv", "python-dotenv"),
    ("cloudinary", "cloudinary"),
)

REQUIRED_ENV_KEYS = ("MONGODB_URI",)
# At least one Cloudinary config shape must be present; checked specially,
# not via REQUIRED_ENV_KEYS (see check_cloudinary_env_keys).


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str
    fix_hint: str | None = None


def check_python_version(version_info: tuple[int, int, int] | None = None) -> CheckResult:
    info = version_info or tuple(sys.version_info[:3])
    ok = (info[0], info[1]) >= MIN_PYTHON
    version_str = f"{info[0]}.{info[1]}.{info[2]}"
    return CheckResult(
        name="Python version",
        passed=ok,
        detail=version_str if ok else f"{version_str} (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})",
        fix_hint=None if ok else f"Install Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ from python.org or your OS package manager.",
    )


def check_package_importable(import_name: str, pip_name: str) -> CheckResult:
    try:
        importlib.import_module(import_name)
        return CheckResult(name=f"package: {pip_name}", passed=True, detail="installed")
    except ImportError:
        return CheckResult(
            name=f"package: {pip_name}",
            passed=False,
            detail="not installed",
            fix_hint="pip install -r requirements.txt",
        )


def parse_env_file(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, value = stripped.partition("=")
            values[key.strip()] = value.strip()
    return values


def check_env_file(env_path: Path, required_keys: tuple[str, ...] = REQUIRED_ENV_KEYS) -> CheckResult:
    if not env_path.exists():
        return CheckResult(
            name=".env file", passed=False, detail="missing",
            fix_hint="cp .env.example .env, then fill in the required values",
        )
    values = parse_env_file(env_path.read_text(encoding="utf-8"))
    missing = [key for key in required_keys if not values.get(key)]
    if missing:
        return CheckResult(
            name=".env file", passed=False, detail=f"missing/empty: {', '.join(missing)}",
            fix_hint=f"Fill in {', '.join(missing)} in .env",
        )
    return CheckResult(name=".env file", passed=True, detail="present, required keys set")


def check_cloudinary_env_keys(env_values: dict[str, str]) -> CheckResult:
    if env_values.get("CLOUDINARY_URL"):
        return CheckResult(name="Cloudinary config", passed=True, detail="CLOUDINARY_URL set")
    separate_keys = ("CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET")
    if all(env_values.get(key) for key in separate_keys):
        return CheckResult(name="Cloudinary config", passed=True, detail="separate cloud name/key/secret set")
    return CheckResult(
        name="Cloudinary config",
        passed=False,
        detail="neither CLOUDINARY_URL nor the separate cloud name/key/secret vars are set",
        fix_hint="Set CLOUDINARY_URL in .env (from your Cloudinary dashboard's 'API Environment variable')",
    )


def check_safe_browsing_env_key(env_values: dict[str, str]) -> CheckResult:
    """Optional — recon's Google Safe Browsing check reports itself as
    unconfigured (not a failure) when this is unset, same as subfinder/
    dirsearch being absent, so this never blocks "this machine is ready".
    """
    if env_values.get("GOOGLE_SAFE_BROWSING_API_KEY"):
        return CheckResult(name="Google Safe Browsing API key", passed=True, detail="GOOGLE_SAFE_BROWSING_API_KEY set")
    return CheckResult(
        name="Google Safe Browsing API key",
        passed=False,
        detail="not set",
        fix_hint="Get a free key from the Google Cloud Console (enable the 'Safe Browsing API') "
        "and set GOOGLE_SAFE_BROWSING_API_KEY in .env, or pass --skip-safe-browsing",
    )


def check_tool_on_path(display_name: str, which_name: str, fix_hint: str) -> CheckResult:
    """A simple presence check for a tool this toolkit can't reliably
    auto-install (e.g. `subfinder`, a compiled Go binary rather than a
    script that can run straight out of a git clone) — PATH only, no
    vendoring fallback, no install attempt.
    """
    on_path = shutil.which(which_name)
    if on_path:
        return CheckResult(name=display_name, passed=True, detail=on_path)
    return CheckResult(name=display_name, passed=False, detail="not found", fix_hint=fix_hint)


def detect_os() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "mac"
    if system == "windows":
        return "windows"
    return "linux"


# Package managers to look for, per OS, in priority order.
_PACKAGE_MANAGERS_BY_OS = {
    "mac": ("brew",),
    "linux": ("apt-get", "dnf", "pacman", "zypper"),
    "windows": ("choco", "winget"),
}


def detect_package_manager(os_name: str | None = None) -> str | None:
    os_name = os_name or detect_os()
    for candidate in _PACKAGE_MANAGERS_BY_OS.get(os_name, ()):
        if shutil.which(candidate):
            return candidate
    return None


def build_package_manager_install_command(package_manager: str, package_name: str) -> list[str] | None:
    """The install command for one package manager + package name, or
    None if that package manager/package combination isn't supported
    here (falls back to the git-clone vendoring path instead).
    """
    commands = {
        "brew": ["brew", "install", package_name],
        "apt-get": ["sudo", "apt-get", "install", "-y", package_name],
        "dnf": ["sudo", "dnf", "install", "-y", package_name],
        "pacman": ["sudo", "pacman", "-S", "--noconfirm", package_name],
        "zypper": ["sudo", "zypper", "install", "-y", package_name],
        "choco": ["choco", "install", package_name, "-y"],
        "winget": ["winget", "install", package_name],
    }
    return commands.get(package_manager)


def build_git_clone_command(repo_url: str, dest: Path) -> list[str]:
    return ["git", "clone", "--depth", "1", repo_url, str(dest)]

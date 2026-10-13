"""Resolve where to find the two optional external tools (`testssl.sh`,
`nikto`) used by `recon/infra_testing.py`: check PATH first, then a
`vendor/` directory inside the repo that `scripts/doctor.py` clones them
into when neither is on PATH and no package manager install succeeded.

Kept separate from infra_testing.py so doctor.py's install logic and
infra_testing.py's run logic both resolve the same way, in one place.

Each resolver returns a tuple of argv parts (not a single string) since
the vendored nikto needs to run as `perl nikto.pl`, two separate argv
elements, not something `subprocess.run` can split out of one string.
"""

from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR_DIR = REPO_ROOT / "vendor"

VENDORED_TESTSSL_PATH = VENDOR_DIR / "testssl.sh" / "testssl.sh"
VENDORED_NIKTO_PATH = VENDOR_DIR / "nikto" / "program" / "nikto.pl"


def resolve_testssl_bin() -> tuple[str, ...]:
    """PATH's `testssl.sh`, else the vendored copy if present, else the
    bare command name (so the caller's own FileNotFoundError message
    fires with a clear "not found" rather than a confusing path error).
    """
    on_path = shutil.which("testssl.sh")
    if on_path:
        return (on_path,)
    if VENDORED_TESTSSL_PATH.exists():
        return (str(VENDORED_TESTSSL_PATH),)
    return ("testssl.sh",)


def resolve_nikto_bin() -> tuple[str, ...]:
    """PATH's `nikto`, else the vendored Perl script run via `perl nikto.pl`."""
    on_path = shutil.which("nikto")
    if on_path:
        return (on_path,)
    perl = shutil.which("perl")
    if VENDORED_NIKTO_PATH.exists() and perl:
        return (perl, str(VENDORED_NIKTO_PATH))
    return ("nikto",)

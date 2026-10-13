"""Resolve where to find the external tools used by `recon/infra_testing.py`,
`recon/subdomain_enum.py`, and `recon/dir_enum.py`: check PATH first, then
(for the ones that support it) a `vendor/` directory inside the repo that
`scripts/doctor.py` clones them into when neither is on PATH and no
package manager install succeeded.

Kept separate from the recon modules so doctor.py's install logic and
each module's run logic both resolve the same way, in one place.

Each resolver returns a tuple of argv parts (not a single string) since
the vendored nikto/dirsearch need to run as `perl nikto.pl`/`python3
dirsearch.py` — two separate argv elements, not something
`subprocess.run` can split out of one string.

`subfinder` has no vendoring fallback: it's a compiled Go binary, not a
script that can run straight out of a git clone like testssl.sh/nikto/
dirsearch can — install it via `go install` or a downloaded release
binary (see docs/pentest-tools-howto.md).
"""

from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VENDOR_DIR = REPO_ROOT / "vendor"

VENDORED_TESTSSL_PATH = VENDOR_DIR / "testssl.sh" / "testssl.sh"
VENDORED_NIKTO_PATH = VENDOR_DIR / "nikto" / "program" / "nikto.pl"
VENDORED_DIRSEARCH_PATH = VENDOR_DIR / "dirsearch" / "dirsearch.py"


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


def resolve_subfinder_bin() -> tuple[str, ...]:
    """PATH's `subfinder`, else the bare command name (no vendoring
    fallback — see module docstring).
    """
    on_path = shutil.which("subfinder")
    return (on_path,) if on_path else ("subfinder",)


def resolve_dirsearch_bin() -> tuple[str, ...]:
    """PATH's `dirsearch`, else the vendored copy run via `python3 dirsearch.py`."""
    on_path = shutil.which("dirsearch")
    if on_path:
        return (on_path,)
    python3 = shutil.which("python3")
    if VENDORED_DIRSEARCH_PATH.exists() and python3:
        return (python3, str(VENDORED_DIRSEARCH_PATH))
    return ("dirsearch",)

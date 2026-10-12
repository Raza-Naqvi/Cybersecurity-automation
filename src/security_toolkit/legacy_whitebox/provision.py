"""LEGACY / WHITE-BOX ONLY — see legacy_whitebox/__init__.py.

Creates a WordPress test user via WP-CLI, which needs a shell on the
app's server — access the security team does not have under the
black-box testing agreement. For the black-box equivalent (POSTing to a
site's own public signup endpoint), see
`security_toolkit.recon.provision.register_via_api`.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from security_toolkit.recon.provision import generate_test_password


@dataclass(frozen=True)
class ProvisionResult:
    username: str
    email: str
    password: str
    detail: str


def provision_wordpress_test_user(
    wp_path: str,
    username: str,
    email: str,
    role: str = "subscriber",
    wp_cli_bin: str = "wp",
) -> ProvisionResult:
    """Create a WordPress user via WP-CLI. Idempotent in practice: if the
    user already exists, WP-CLI returns a non-zero exit and this surfaces
    that as a RuntimeError rather than silently continuing — re-run with a
    different username, or treat the existing account as already set up.
    """
    password = generate_test_password()
    try:
        result = subprocess.run(
            [
                wp_cli_bin,
                "user",
                "create",
                username,
                email,
                f"--role={role}",
                f"--user_pass={password}",
                f"--path={wp_path}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"'{wp_cli_bin}' not found; is WP-CLI installed?") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("wp user create timed out after 60s") from exc

    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "wp user create failed").strip())

    return ProvisionResult(
        username=username, email=email, password=password, detail=(result.stdout or "").strip()
    )

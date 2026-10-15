"""Shared URL scope-check used by every black-box module that makes HTTP
requests (recon fingerprinting, the IDOR tester, auth login, provisioning).
One implementation, reused everywhere, so "never request a URL outside
the authorized base_url" is enforced the same way across the toolkit
instead of each module re-implementing it slightly differently.
"""

from __future__ import annotations

from urllib.parse import urlparse

from security_toolkit.config import Target


class OutOfScopeError(RuntimeError):
    """Raised when a URL falls outside the authorized target's base_url."""


def require_in_scope(url: str, target: Target) -> None:
    if not target.base_url:
        raise OutOfScopeError(f"Target '{target.name}' has no base_url configured")
    base = urlparse(target.base_url)
    candidate = urlparse(url)
    if (candidate.scheme, candidate.netloc) != (base.scheme, base.netloc):
        raise OutOfScopeError(
            f"Refusing to request {url!r} — it is outside authorized base_url "
            f"{target.base_url!r} for target '{target.name}'."
        )


def resolve_in_scope_url(target: Target, path_or_url: str) -> str:
    """Join a relative path onto the target's base_url (or pass an
    already-absolute URL through), then enforce it's in scope.
    """
    url = (
        path_or_url
        if path_or_url.startswith("http")
        else f"{(target.base_url or '').rstrip('/')}/{path_or_url.lstrip('/')}"
    )
    require_in_scope(url, target)
    return url

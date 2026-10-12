"""LEGACY / WHITE-BOX ONLY — not used under the current engagement model.

Everything in this package needs access the security team does not have
under the dev/security black-box testing agreement: a filesystem path on
the app's server (`wp_path`), direct database credentials, or a shell on
the server to run WP-CLI. None of that is available when testing a site
you don't have code or server access to.

Kept in the repo (not deleted) in case a future engagement is ever
explicitly scoped as white-box/internal with the dev team's sign-off —
but it is not part of the normal workflow. See recon/ for the black-box
equivalents (HTTP-only: fingerprinting, auth/session testing, IDOR, etc.)
and README.md's "Legacy (white-box only)" section before using anything
here.
"""

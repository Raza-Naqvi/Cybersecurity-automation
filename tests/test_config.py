import pytest

from unittest.mock import patch

from security_toolkit.config import (
    ScopeError,
    list_authorized_targets,
    load_authorized_target,
    load_credentials_from_env,
    load_test_credentials,
)


def test_load_authorized_target_returns_match():
    doc = {"name": "staging", "type": "wordpress", "environment": "staging", "base_url": "https://staging.test"}
    with patch("security_toolkit.scope_db.load_target", return_value=doc):
        target = load_authorized_target("staging")
    assert target.name == "staging"
    assert target.base_url == "https://staging.test"


def test_load_authorized_target_rejects_unknown_name():
    with patch("security_toolkit.scope_db.load_target", return_value=None), patch(
        "security_toolkit.scope_db.list_all_targets", return_value=({"name": "staging"},)
    ):
        with pytest.raises(ScopeError):
            load_authorized_target("production")


def test_load_authorized_target_raises_scope_error_on_connection_failure():
    with patch("security_toolkit.scope_db.load_target", side_effect=RuntimeError("auth failed")):
        with pytest.raises(ScopeError, match="Could not reach"):
            load_authorized_target("anything")


def test_list_authorized_targets_is_immutable_tuple():
    with patch("security_toolkit.scope_db.list_all_targets", return_value=({"name": "a"}, {"name": "b"})):
        targets = list_authorized_targets()
    assert isinstance(targets, tuple)
    assert [t.name for t in targets] == ["a", "b"]


def test_list_authorized_targets_raises_scope_error_on_connection_failure():
    with patch("security_toolkit.scope_db.list_all_targets", side_effect=RuntimeError("auth failed")):
        with pytest.raises(ScopeError, match="Could not reach"):
            list_authorized_targets()


def test_load_credentials_from_env_reads_dotenv_path(tmp_path, monkeypatch):
    monkeypatch.delenv("IDOR_USER_A_USERNAME", raising=False)
    monkeypatch.delenv("IDOR_USER_A_PASSWORD", raising=False)
    env_path = tmp_path / ".env"
    env_path.write_text("IDOR_USER_A_USERNAME=a@test.com\nIDOR_USER_A_PASSWORD=secret\n")

    creds = load_credentials_from_env("IDOR_USER_A", dotenv_path=env_path)

    assert creds.username == "a@test.com"
    assert creds.password == "secret"


def test_load_credentials_from_env_raises_when_missing(tmp_path, monkeypatch):
    monkeypatch.delenv("IDOR_USER_B_USERNAME", raising=False)
    monkeypatch.delenv("IDOR_USER_B_PASSWORD", raising=False)
    env_path = tmp_path / ".env"
    env_path.write_text("")

    with pytest.raises(ScopeError):
        load_credentials_from_env("IDOR_USER_B", dotenv_path=env_path)


def test_load_test_credentials_returns_credentials_from_db():
    stored = type("Stored", (), {"username": "a@test.com", "password": "pw"})()
    with patch("security_toolkit.credentials_db.load_credentials", return_value=stored):
        creds = load_test_credentials("cheerlytics", "IDOR_USER_A")
    assert creds.username == "a@test.com"
    assert creds.password == "pw"


def test_load_test_credentials_raises_when_not_stored():
    with patch("security_toolkit.credentials_db.load_credentials", return_value=None):
        with pytest.raises(ScopeError):
            load_test_credentials("cheerlytics", "IDOR_USER_A")


def test_load_test_credentials_raises_scope_error_on_connection_failure():
    with patch("security_toolkit.credentials_db.load_credentials", side_effect=RuntimeError("auth failed")):
        with pytest.raises(ScopeError, match="Could not reach"):
            load_test_credentials("cheerlytics", "IDOR_USER_A")

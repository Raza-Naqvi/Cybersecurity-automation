import json

import pytest

from security_toolkit.scope_manager import (
    build_auth_block,
    get_target,
    list_target_names,
    load_scope_data,
    remove_target,
    save_scope_data,
    upsert_target,
)


def test_load_scope_data_returns_empty_structure_when_missing(tmp_path):
    data = load_scope_data(tmp_path / "does-not-exist.json")
    assert data == {"authorized_targets": []}


def test_load_scope_data_reads_existing_file(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"authorized_targets": [{"name": "a"}]}))
    data = load_scope_data(path)
    assert data["authorized_targets"] == [{"name": "a"}]


def test_upsert_target_adds_new_target():
    data = {"authorized_targets": []}
    result = upsert_target(data, {"name": "a", "base_url": "https://a.test"})
    assert list_target_names(result) == ("a",)
    # original is untouched
    assert data["authorized_targets"] == []


def test_upsert_target_replaces_existing_by_name():
    data = {"authorized_targets": [{"name": "a", "base_url": "https://old.test"}]}
    result = upsert_target(data, {"name": "a", "base_url": "https://new.test"})
    assert len(result["authorized_targets"]) == 1
    assert get_target(result, "a")["base_url"] == "https://new.test"


def test_upsert_target_requires_name():
    with pytest.raises(ValueError):
        upsert_target({"authorized_targets": []}, {"base_url": "https://a.test"})


def test_remove_target_removes_matching_entry():
    data = {"authorized_targets": [{"name": "a"}, {"name": "b"}]}
    result = remove_target(data, "a")
    assert list_target_names(result) == ("b",)


def test_remove_target_is_noop_when_absent():
    data = {"authorized_targets": [{"name": "a"}]}
    result = remove_target(data, "nonexistent")
    assert list_target_names(result) == ("a",)


def test_get_target_returns_none_when_absent():
    assert get_target({"authorized_targets": []}, "x") is None


def test_save_scope_data_writes_valid_json(tmp_path):
    path = tmp_path / "nested" / "scope.json"
    save_scope_data(path, {"authorized_targets": [{"name": "a"}]})
    assert json.loads(path.read_text())["authorized_targets"] == [{"name": "a"}]


def test_build_auth_block_wordpress():
    block = build_auth_block("wordpress", login_url="https://x.test/wp-login.php")
    assert block == {"type": "wordpress", "login_url": "https://x.test/wp-login.php"}


def test_build_auth_block_form_session_with_csrf():
    block = build_auth_block(
        "form_session",
        login_url="https://x.test/login",
        username_field="email",
        csrf_page_url="https://x.test/login",
        csrf_field_name="_token",
    )
    assert block["csrf"] == {"page_url": "https://x.test/login", "field_name": "_token"}
    assert block["username_field"] == "email"


def test_build_auth_block_form_session_without_csrf_omits_key():
    block = build_auth_block("form_session", login_url="https://x.test/login")
    assert "csrf" not in block


def test_build_auth_block_json_token():
    block = build_auth_block("json_token", login_url="https://x.test/api/login", token_path="data.token")
    assert block["token_path"] == "data.token"
    assert block["header_prefix"] == "Bearer "


def test_build_auth_block_rejects_unknown_type():
    with pytest.raises(ValueError):
        build_auth_block("sso-magic", login_url="https://x.test/login")


def test_build_auth_block_requires_login_url():
    with pytest.raises(ValueError):
        build_auth_block("wordpress", login_url="")

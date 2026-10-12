import json

import pytest

from security_toolkit.config import ScopeError, list_authorized_targets, load_authorized_target


def _write_scope(tmp_path, targets):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({"authorized_targets": targets}))
    return scope_path


def test_load_authorized_target_returns_match(tmp_path):
    scope_path = _write_scope(
        tmp_path,
        [{"name": "staging", "type": "wordpress", "environment": "staging", "base_url": "https://staging.test"}],
    )
    target = load_authorized_target("staging", scope_path=scope_path)
    assert target.name == "staging"
    assert target.base_url == "https://staging.test"


def test_load_authorized_target_rejects_unknown_name(tmp_path):
    scope_path = _write_scope(tmp_path, [{"name": "staging"}])
    with pytest.raises(ScopeError):
        load_authorized_target("production", scope_path=scope_path)


def test_missing_scope_file_raises(tmp_path):
    with pytest.raises(ScopeError):
        load_authorized_target("anything", scope_path=tmp_path / "does-not-exist.json")


def test_list_authorized_targets_is_immutable_tuple(tmp_path):
    scope_path = _write_scope(tmp_path, [{"name": "a"}, {"name": "b"}])
    targets = list_authorized_targets(scope_path)
    assert isinstance(targets, tuple)
    assert [t.name for t in targets] == ["a", "b"]

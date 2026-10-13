from security_toolkit.env_file import update_env_file


def test_update_env_file_creates_new_file_with_keys(tmp_path):
    path = tmp_path / ".env"
    update_env_file(path, {"FOO": "bar", "BAZ": "qux"})
    content = path.read_text()
    assert "FOO=bar" in content
    assert "BAZ=qux" in content


def test_update_env_file_preserves_other_lines(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# a comment\nDB_HOST=127.0.0.1\nUNRELATED=keep-me\n")

    update_env_file(path, {"DB_HOST": "10.0.0.1"})

    content = path.read_text()
    assert "# a comment" in content
    assert "DB_HOST=10.0.0.1" in content
    assert "DB_HOST=127.0.0.1" not in content
    assert "UNRELATED=keep-me" in content


def test_update_env_file_appends_missing_key(tmp_path):
    path = tmp_path / ".env"
    path.write_text("EXISTING=1\n")

    update_env_file(path, {"NEW_KEY": "value"})

    content = path.read_text()
    assert "EXISTING=1" in content
    assert "NEW_KEY=value" in content


def test_update_env_file_updates_multiple_keys_once(tmp_path):
    path = tmp_path / ".env"
    path.write_text("A=old\nB=old\n")

    update_env_file(path, {"A": "new-a", "B": "new-b"})

    content = path.read_text()
    assert content.count("A=") == 1
    assert "A=new-a" in content
    assert "B=new-b" in content

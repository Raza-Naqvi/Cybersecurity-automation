import pytest

from security_toolkit.legacy_whitebox.monthly_checklist import (
    check_backup_freshness,
    summarize_access_log_spikes,
)


def test_check_backup_freshness_flags_missing_dir(tmp_path):
    result = check_backup_freshness(str(tmp_path / "nope"))
    assert result.is_stale is True
    assert result.newest_file is None


def test_check_backup_freshness_flags_stale_backup(tmp_path):
    backup_file = tmp_path / "backup-old.zip"
    backup_file.write_text("data")
    import os
    import time

    old_time = time.time() - (10 * 86400)
    os.utime(backup_file, (old_time, old_time))

    result = check_backup_freshness(str(tmp_path), max_age_days=2)

    assert result.is_stale is True
    assert result.age_days > 2


def test_check_backup_freshness_accepts_fresh_backup(tmp_path):
    backup_file = tmp_path / "backup-fresh.zip"
    backup_file.write_text("data")

    result = check_backup_freshness(str(tmp_path), max_age_days=2)

    assert result.is_stale is False


def test_summarize_access_log_spikes_counts_ips(tmp_path):
    log_path = tmp_path / "access.log"
    log_path.write_text(
        "1.1.1.1 - - [GET /]\n"
        "1.1.1.1 - - [GET /]\n"
        "2.2.2.2 - - [GET /]\n"
    )

    top = summarize_access_log_spikes(str(log_path), top_n=5)

    assert top[0] == ("1.1.1.1", 2)
    assert ("2.2.2.2", 1) in top


def test_summarize_access_log_spikes_missing_file_raises(tmp_path):
    with pytest.raises(ValueError):
        summarize_access_log_spikes(str(tmp_path / "missing.log"))

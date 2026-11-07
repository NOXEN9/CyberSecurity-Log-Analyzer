import csv
import json
from datetime import datetime, timedelta

import pytest

import log_analyzer as la

HEADER = "Timestamp,User,IP,Status\n"
BASE = datetime(2026, 11, 7, 9, 0, 0)


def write_csv(path, body, header=HEADER):
    path.write_text(header + body, encoding="utf-8")
    return str(path)


def failed(ip, minutes, user="admin", seconds=0):
    """Build a parsed 'Failed' event `minutes` after BASE."""
    return {
        "timestamp": BASE + timedelta(minutes=minutes, seconds=seconds),
        "user": user,
        "ip": ip,
        "status": "Failed",
    }


# ---------------- parsing ----------------
def test_parse_valid_row():
    row = {"Timestamp": "2026-11-07 09:00:00", "User": " admin ", "IP": "8.8.8.8", "Status": "failed"}
    event = la.parse_event(row)
    assert event["user"] == "admin"
    assert event["ip"] == "8.8.8.8"
    assert event["status"] == "Failed"
    assert event["timestamp"] == datetime(2026, 11, 7, 9, 0, 0)


@pytest.mark.parametrize("row, reason", [
    ({"Timestamp": "yesterday", "User": "a", "IP": "8.8.8.8", "Status": "Failed"}, "invalid timestamp"),
    ({"Timestamp": "2026-11-07 09:00:00", "User": "a", "IP": "999.1.1.1", "Status": "Failed"}, "invalid IP"),
    ({"Timestamp": "2026-11-07 09:00:00", "User": "  ", "IP": "8.8.8.8", "Status": "Failed"}, "empty field 'User'"),
    ({"Timestamp": "2026-11-07 09:00:00", "User": "a", "IP": "8.8.8.8", "Status": None}, "missing field 'Status'"),
    ({"Timestamp": "2026-11-07 09:00:00", "User": "a", "IP": "8.8.8.8", "Status": "Failed", None: ["x"]}, "too many fields"),
])
def test_parse_rejects_corrupt_rows(row, reason):
    with pytest.raises(ValueError, match=reason):
        la.parse_event(row)


# ---------------- loading ----------------
def test_load_logs_skips_corrupt_rows_and_keeps_good_ones(tmp_path):
    path = write_csv(tmp_path / "logs.csv", (
        "2026-11-07 09:00:00,admin,8.8.8.8,Failed\n"
        "garbage,admin,8.8.8.8,Failed\n"
        "2026-11-07 09:02:00,sara\n"
        "2026-11-07 09:03:00,sara,1.1.1.1,Success\n"
    ))
    events, skipped = la.load_logs(path)
    assert len(events) == 2
    assert [item["line"] for item in skipped] == [3, 4]
    assert "invalid timestamp" in skipped[0]["reason"]
    assert "missing field" in skipped[1]["reason"]


def test_load_logs_missing_file_raises_clear_error(tmp_path):
    with pytest.raises(la.LogFileError, match="not found"):
        la.load_logs(str(tmp_path / "nope.csv"))


def test_load_logs_empty_file_raises(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("")
    with pytest.raises(la.LogFileError, match="empty"):
        la.load_logs(str(path))


def test_load_logs_missing_columns_raises(tmp_path):
    path = write_csv(tmp_path / "bad.csv", "2026-11-07 09:00:00,admin\n", header="Timestamp,User\n")
    with pytest.raises(la.LogFileError, match="IP, Status"):
        la.load_logs(path)


def test_load_logs_header_only_returns_no_events(tmp_path):
    events, skipped = la.load_logs(write_csv(tmp_path / "h.csv", ""))
    assert events == [] and skipped == []


def test_load_logs_directory_raises(tmp_path):
    with pytest.raises(la.LogFileError):
        la.load_logs(str(tmp_path))


def test_load_logs_binary_garbage_raises(tmp_path):
    path = tmp_path / "bin.csv"
    path.write_bytes(b"\xff\xfe\x00\x80\x81\x82" * 50)
    with pytest.raises(la.LogFileError):
        la.load_logs(str(path))


# ---------------- counting ----------------
def test_count_failed_logins_ignores_success():
    events = [failed("1.1.1.1", 0, "admin"), failed("1.1.1.1", 1, "admin"), failed("2.2.2.2", 2, "sara")]
    events.append({**failed("1.1.1.1", 3, "admin"), "status": "Success"})
    per_user, per_ip = la.count_failed_logins(events)
    assert per_user == {"admin": 2, "sara": 1}
    assert per_ip == {"1.1.1.1": 2, "2.2.2.2": 1}


# ---------------- brute force window ----------------
def test_exactly_five_failures_is_not_an_alert():
    events = [failed("1.1.1.1", i) for i in range(5)]
    alerts, peak = la.detect_brute_force(events)
    assert alerts == []
    assert peak["1.1.1.1"] == 5


def test_six_failures_in_window_is_an_alert():
    events = [failed("1.1.1.1", i) for i in range(6)]
    alerts, _ = la.detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "1.1.1.1"
    assert alerts[0]["attempts_in_window"] == 6


def test_failures_spread_over_more_than_ten_minutes_are_not_an_alert():
    events = [failed("1.1.1.1", i * 3) for i in range(8)]  # one every 3 minutes
    alerts, _ = la.detect_brute_force(events)
    assert alerts == []


def test_attempt_exactly_ten_minutes_apart_still_counts():
    events = [failed("1.1.1.1", m) for m in (0, 2, 4, 6, 8, 10)]
    alerts, _ = la.detect_brute_force(events)
    assert len(alerts) == 1


def test_attempt_just_over_ten_minutes_does_not_count():
    events = [failed("1.1.1.1", m) for m in (0, 2, 4, 6, 8)]
    events.append(failed("1.1.1.1", 10, seconds=1))
    alerts, _ = la.detect_brute_force(events)
    assert alerts == []


def test_long_attack_produces_a_single_alert():
    events = [failed("1.1.1.1", 0, seconds=i * 20) for i in range(20)]
    alerts, _ = la.detect_brute_force(events)
    assert len(alerts) == 1


def test_second_burst_after_quiet_period_raises_second_alert():
    first = [failed("1.1.1.1", i) for i in range(6)]
    second = [failed("1.1.1.1", 60 + i) for i in range(6)]
    alerts, _ = la.detect_brute_force(first + second)
    assert len(alerts) == 2


def test_ips_are_counted_separately():
    events = []
    for i in range(4):
        events.append(failed("1.1.1.1", i))
        events.append(failed("2.2.2.2", i))
    alerts, _ = la.detect_brute_force(events)
    assert alerts == []


def test_unsorted_events_are_handled():
    events = [failed("1.1.1.1", i) for i in range(6)]
    events.reverse()
    alerts, _ = la.detect_brute_force(events)
    assert len(alerts) == 1


def test_success_events_do_not_count_toward_window():
    events = [failed("1.1.1.1", i) for i in range(5)]
    events.append({**failed("1.1.1.1", 5), "status": "Success"})
    alerts, _ = la.detect_brute_force(events)
    assert alerts == []


def test_alert_lists_targeted_users():
    users = ["admin", "root", "admin", "test", "admin", "sara"]
    events = [failed("1.1.1.1", i, user) for i, user in enumerate(users)]
    alerts, _ = la.detect_brute_force(events)
    assert alerts[0]["users_targeted"] == ["admin", "root", "sara", "test"]


def test_custom_threshold_and_window():
    events = [failed("1.1.1.1", i) for i in range(3)]
    alerts, _ = la.detect_brute_force(events, max_attempts=2, window_minutes=5)
    assert len(alerts) == 1


# ---------------- reports ----------------
def test_export_json_and_csv(tmp_path):
    events = [failed("1.1.1.1", i) for i in range(6)] + [failed("2.2.2.2", 0, "sara")]
    report = la.build_report(events, skipped=[{"line": 9, "reason": "bad", "raw": {}}])

    json_path = tmp_path / "r.json"
    csv_path = tmp_path / "r.csv"
    la.export_json(report, json_path)
    la.export_csv(report, csv_path)

    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["summary"]["failed_logins_total"] == 7
    assert loaded["summary"]["flagged_ips"] == 1
    assert loaded["summary"]["skipped_records"] == 1

    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows[0]["IP"] == "1.1.1.1"
    assert rows[0]["Flagged"] == "YES"
    assert rows[1]["IP"] == "2.2.2.2"
    assert rows[1]["Flagged"] == "NO"


# ---------------- command line ----------------
def test_main_end_to_end_with_corrupt_rows(tmp_path, capsys):
    body = "".join(f"2026-11-07 09:0{i}:00,admin,8.8.8.8,Failed\n" for i in range(6))
    body += "bad line\n"
    log = write_csv(tmp_path / "logs.csv", body)
    out = tmp_path / "reports"

    code = la.main([log, "--out-dir", str(out)])

    assert code == 0
    assert (out / "report.json").exists()
    assert (out / "report.csv").exists()
    text = capsys.readouterr().out
    assert "[ALERT" in text
    assert "[SKIPPED line 8]" in text


def test_main_missing_file_returns_error_code(tmp_path, capsys):
    code = la.main([str(tmp_path / "nope.csv"), "--out-dir", str(tmp_path)])
    assert code == 1
    assert "[ERROR]" in capsys.readouterr().out
    assert not (tmp_path / "report.json").exists()

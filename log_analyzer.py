"""
===================================================================
PROJECT: Cyber Security Log Analyzer
AUTHOR: ASAD DAFALLA / Noxen
VERSION: 4.0.0 (Full project: validation + JSON/CSV report + tests)
NOTE: Reads a login log CSV, extracts time / user / IP / event type,
      counts failed logins, detects brute-force IPs (more than 5
      failed attempts within 10 minutes) and writes JSON + CSV
      reports. Corrupt rows are skipped and reported, never crash
      the run.

EXPECTED CSV COLUMNS: Timestamp, User, IP, Status
  Timestamp format : YYYY-MM-DD HH:MM:SS
  Status           : event type, e.g. Failed / Success
===================================================================
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
from collections import deque
from datetime import datetime, timedelta

REQUIRED_COLUMNS = ["Timestamp", "User", "IP", "Status"]
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
FAILED_STATUS = "Failed"


class LogFileError(Exception):
    """Raised when the whole log file cannot be used (missing, empty, bad header)."""


# ------------------------------------------------------------------
# Step 1: Parsing and loading
# ------------------------------------------------------------------
def parse_event(row):
    """Validate one CSV row and return a clean event dict.

    Raises ValueError with a readable reason if the row is corrupt.
    """
    if None in row:
        raise ValueError("too many fields in row")

    values = {}
    for column in REQUIRED_COLUMNS:
        value = row.get(column)
        if value is None:
            raise ValueError(f"missing field '{column}'")
        value = value.strip()
        if not value:
            raise ValueError(f"empty field '{column}'")
        values[column] = value

    try:
        timestamp = datetime.strptime(values["Timestamp"], TIME_FORMAT)
    except ValueError:
        raise ValueError(f"invalid timestamp '{values['Timestamp']}'")

    try:
        ip = str(ipaddress.ip_address(values["IP"]))
    except ValueError:
        raise ValueError(f"invalid IP '{values['IP']}'")

    return {
        "timestamp": timestamp,
        "user": values["User"],
        "ip": ip,
        "status": values["Status"].capitalize(),
    }


def load_logs(file_path):
    """Read the CSV and return (events, skipped).

    events  : list of clean event dicts
    skipped : list of {"line": n, "reason": text, "raw": row} for corrupt rows
    """
    events = []
    skipped = []

    try:
        with open(file_path, "r", newline="", encoding="utf-8-sig") as file_input:
            reader = csv.DictReader(file_input)

            if reader.fieldnames is None:
                raise LogFileError(f"'{file_path}' is empty.")

            header = [name.strip() for name in reader.fieldnames if name]
            missing = [c for c in REQUIRED_COLUMNS if c not in header]
            if missing:
                raise LogFileError(
                    f"'{file_path}' is missing required column(s): {', '.join(missing)}"
                )
            reader.fieldnames = [name.strip() if name else name for name in reader.fieldnames]

            for row in reader:
                line_number = reader.line_num
                try:
                    events.append(parse_event(row))
                except ValueError as error:
                    skipped.append({
                        "line": line_number,
                        "reason": str(error),
                        "raw": {str(k): v for k, v in row.items()},
                    })
    except FileNotFoundError:
        raise LogFileError(f"Log file not found: '{file_path}'")
    except IsADirectoryError:
        raise LogFileError(f"'{file_path}' is a directory, not a log file.")
    except PermissionError:
        raise LogFileError(f"No permission to read '{file_path}'.")
    except UnicodeDecodeError:
        raise LogFileError(f"'{file_path}' is not a valid UTF-8 text file.")
    except csv.Error as error:
        raise LogFileError(f"'{file_path}' could not be parsed as CSV: {error}")

    return events, skipped


# ------------------------------------------------------------------
# Step 2: Analysis
# ------------------------------------------------------------------
def count_failed_logins(events):
    """Return (failed_per_user, failed_per_ip) dictionaries."""
    per_user = {}
    per_ip = {}
    for event in events:
        if event["status"] != FAILED_STATUS:
            continue
        per_user[event["user"]] = per_user.get(event["user"], 0) + 1
        per_ip[event["ip"]] = per_ip.get(event["ip"], 0) + 1
    return per_user, per_ip


def detect_brute_force(events, max_attempts=5, window_minutes=10):
    """Find IPs with MORE than `max_attempts` failed logins inside the window.

    Returns (alerts, peak_per_ip):
      alerts       : one alert per attack burst (not one per extra attempt)
      peak_per_ip  : the highest number of failures seen in one window per IP

    Events are sorted by time first, so an unordered file is fine.
    A failure exactly `window_minutes` before the current one still counts.
    """
    window = timedelta(minutes=window_minutes)
    failed = sorted(
        (e for e in events if e["status"] == FAILED_STATUS),
        key=lambda e: e["timestamp"],
    )

    history = {}      # ip -> deque of (timestamp, user) inside the window
    in_alert = {}     # ip -> True while a burst is already reported
    peak_per_ip = {}
    alerts = []

    for event in failed:
        ip = event["ip"]
        now = event["timestamp"]
        attempts = history.setdefault(ip, deque())
        attempts.append((now, event["user"]))

        while attempts and now - attempts[0][0] > window:
            attempts.popleft()

        count = len(attempts)
        peak_per_ip[ip] = max(peak_per_ip.get(ip, 0), count)

        if count > max_attempts:
            if not in_alert.get(ip):
                in_alert[ip] = True
                alerts.append({
                    "ip": ip,
                    "alert_time": now.strftime(TIME_FORMAT),
                    "first_attempt_in_window": attempts[0][0].strftime(TIME_FORMAT),
                    "attempts_in_window": count,
                    "users_targeted": sorted({user for _, user in attempts}),
                })
        else:
            in_alert[ip] = False

    return alerts, peak_per_ip


# ------------------------------------------------------------------
# Step 3: Reporting
# ------------------------------------------------------------------
def build_report(events, skipped, max_attempts=5, window_minutes=10):
    per_user, per_ip = count_failed_logins(events)
    alerts, peak_per_ip = detect_brute_force(events, max_attempts, window_minutes)
    flagged_ips = {alert["ip"] for alert in alerts}

    return {
        "summary": {
            "valid_events": len(events),
            "skipped_records": len(skipped),
            "failed_logins_total": sum(per_user.values()),
            "flagged_ips": len(flagged_ips),
            "rule": f"more than {max_attempts} failed attempts from one IP within {window_minutes} minutes",
        },
        "failed_logins_per_user": per_user,
        "failed_logins_per_ip": per_ip,
        "peak_failures_in_window_per_ip": peak_per_ip,
        "alerts": alerts,
        "skipped_records": skipped,
    }


def export_json(report, output_path):
    with open(output_path, "w", encoding="utf-8") as file_out:
        json.dump(report, file_out, indent=4, ensure_ascii=False)


def export_csv(report, output_path):
    """One row per IP that had failed logins."""
    flagged_ips = {alert["ip"] for alert in report["alerts"]}
    users_by_ip = {alert["ip"]: alert["users_targeted"] for alert in report["alerts"]}

    with open(output_path, "w", newline="", encoding="utf-8") as file_out:
        writer = csv.writer(file_out)
        writer.writerow(["IP", "Failed_Attempts", "Peak_In_Window", "Flagged", "Users_Targeted"])
        rows = sorted(report["failed_logins_per_ip"].items(), key=lambda item: -item[1])
        for ip, total in rows:
            writer.writerow([
                ip,
                total,
                report["peak_failures_in_window_per_ip"].get(ip, 0),
                "YES" if ip in flagged_ips else "NO",
                ";".join(users_by_ip.get(ip, [])),
            ])


# ------------------------------------------------------------------
# Command line entry point
# ------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(description="Cyber Security Log Analyzer")
    parser.add_argument("log_file", help="path to the login log CSV")
    parser.add_argument("--out-dir", default=".", help="folder for report.json and report.csv")
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--window-minutes", type=int, default=10)
    args = parser.parse_args(argv)

    print("--- Cyber Security Log Analyzer ---")

    try:
        events, skipped = load_logs(args.log_file)
    except LogFileError as error:
        print(f"[ERROR] {error}")
        return 1

    report = build_report(events, skipped, args.max_attempts, args.window_minutes)

    try:
        os.makedirs(args.out_dir, exist_ok=True)
        json_path = os.path.join(args.out_dir, "report.json")
        csv_path = os.path.join(args.out_dir, "report.csv")
        export_json(report, json_path)
        export_csv(report, csv_path)
    except OSError as error:
        print(f"[ERROR] Could not write reports: {error}")
        return 1

    summary = report["summary"]
    print(f"Valid events     : {summary['valid_events']}")
    print(f"Skipped records  : {summary['skipped_records']}")
    print(f"Failed logins    : {summary['failed_logins_total']}")
    for alert in report["alerts"]:
        print(f"[ALERT {alert['alert_time']}] IP {alert['ip']}: "
              f"{alert['attempts_in_window']} failed attempts within the window")
    if not report["alerts"]:
        print("No brute-force activity detected.")
    for item in skipped:
        print(f"[SKIPPED line {item['line']}] {item['reason']}")
    print(f"Reports written to '{json_path}' and '{csv_path}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

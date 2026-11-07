# Cyber Security Log Analyzer 🛡️

A modular Python security tool that simulates a SIEM-style log parser. It reads authentication logs, counts failed logins, detects brute-force attacks, and exports JSON and CSV reports. Corrupt records and missing files are handled gracefully, and the whole project is covered by `pytest` tests.

**Author:** ASAD DAFALLA / Noxen
**Version:** 4.0.0

## ✨ Features
- **Log parsing:** Extracts the timestamp, user, source IP, and event type from every row.
- **Failed login counting:** Totals per user and per IP.
- **Brute-force detection:** Flags any IP with **more than 5 failed attempts within 10 minutes** (sliding time window). One alert is raised per attack burst, not one per extra attempt.
- **Dual reports:** `report.json` (full details) and `report.csv` (one row per IP).
- **Fault tolerance:** A missing, empty, or malformed file produces a clear error message. A corrupt row is skipped and listed in the report instead of crashing the run.
- **Tested:** 29 `pytest` tests covering parsing, error handling, the time window edge cases, and report export.

## 📂 Project Structure
```
log_analyzer/
├── log_analyzer.py          # The analyzer (functions + command line)
├── tests/
│   └── test_log_analyzer.py # Test suite
└── README.md
```

## 🧩 Functions
| Function | Purpose |
|---|---|
| `parse_event(row)` | Validates one CSV row (timestamp format, IP address, empty fields) and returns a clean event. Raises `ValueError` with the reason if the row is corrupt. |
| `load_logs(file_path)` | Reads the CSV and returns `(events, skipped)`. Raises `LogFileError` if the file is missing, empty, unreadable, or lacks required columns. |
| `count_failed_logins(events)` | Returns failed login counts per user and per IP. |
| `detect_brute_force(events, max_attempts=5, window_minutes=10)` | Sliding-window detection. Returns the alerts and the peak failure count per IP. |
| `build_report(events, skipped, ...)` | Combines all results into one report dictionary. |
| `export_json(report, path)` / `export_csv(report, path)` | Write the reports to disk. |
| `main(argv)` | Command line entry point. Returns `0` on success and `1` on error. |

## 📥 Input Format
A CSV file with these columns (extra spaces are trimmed):

```csv
Timestamp,User,IP,Status
2026-11-07 09:00:00,admin,203.0.113.5,Failed
2026-11-07 09:10:00,sara,198.51.100.7,Success
```

| Column | Rule |
|---|---|
| `Timestamp` | `YYYY-MM-DD HH:MM:SS` |
| `User` | Must not be empty |
| `IP` | Valid IPv4 or IPv6 address |
| `Status` | Event type, such as `Failed` or `Success` (case-insensitive). Only `Failed` counts toward detection. |

## 🚀 Usage
```bash
python log_analyzer.py IoC.csv --out-dir reports
```

| Option | Default | Description |
|---|---|---|
| `log_file` | required | Path to the login log CSV |
| `--out-dir` | `.` | Folder where `report.json` and `report.csv` are written |
| `--max-attempts` | `5` | Alert when failures are **more than** this number |
| `--window-minutes` | `10` | Size of the time window |

A failure exactly `window-minutes` before the current one still counts inside the window.

### Example output
```
--- Cyber Security Log Analyzer ---
Valid events     : 11
Skipped records  : 5
Failed logins    : 9
[ALERT 2026-11-07 09:05:00] IP 203.0.113.5: 6 failed attempts within the window
[SKIPPED line 13] invalid timestamp 'not-a-date'
[SKIPPED line 14] invalid IP '999.1.1.1'
[SKIPPED line 15] empty field 'User'
[SKIPPED line 16] missing field 'IP'
[SKIPPED line 17] too many fields in row
Reports written to 'reports/report.json' and 'reports/report.csv'.
```

## 📊 Reports
**`report.json`** contains:
- `summary`: valid events, skipped records, total failed logins, flagged IPs, and the rule used
- `failed_logins_per_user` and `failed_logins_per_ip`
- `peak_failures_in_window_per_ip`
- `alerts`: IP, alert time, first attempt in the window, attempt count, and users targeted
- `skipped_records`: line number, reason, and the raw row

**`report.csv`** has one row per IP with failures:

```csv
IP,Failed_Attempts,Peak_In_Window,Flagged,Users_Targeted
203.0.113.5,7,7,YES,admin;root;test
198.51.100.8,2,1,NO,
```

## 🧪 Running the Tests
Run it from the project folder (the one containing `log_analyzer.py`):

```bash
python -m pytest
```

The tests cover valid and corrupt rows, missing/empty/binary files, the exact 5-vs-6 attempt boundary, the 10-minute boundary, unsorted logs, multiple IPs, repeated bursts, report export, and the command line exit codes.

## 💻 Tech Stack
- **Language:** Python 3.x (standard library only: `csv`, `json`, `ipaddress`, `argparse`, `datetime`, `collections`)
- **Testing:** `pytest`
- **Concepts:** Functions and return values, custom exceptions, input validation, sliding time windows with `deque`, CSV and JSON I/O, `__main__` execution control

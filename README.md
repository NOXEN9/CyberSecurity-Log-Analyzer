# Cyber Security Log Analyzer 🛡️

A professional, modular Python-based security tool that simulates a SIEM system parser to analyze network authentication logs and detect potential brute-force attacks.

## ✨ What's New in v2.0.0 (Modular Update)
- **Production-Ready Architecture:** Completely refactored from a single-use script into reusable, independent functions.
- **Parametric Execution:** Functions now accept parameters and arguments, allowing the script to parse any given input log file dynamically.
- **Cross-Format Pipeline:** Seamlessly imports raw spreadsheet logs from `IoC.csv` and automatically exports calculated summaries into structured `failed_report_1.json`.

## 📂 Project Structure & Functions
- `load_logs(file_path)`: Dynamically handles the ingestion and parsing of CSV log files.
- `analyze_brute_force(logon_events)`: The core security logic engine that calculates failed logins per user using dictionaries.
- `export_report(report_data, output_path)`: Exports compiled intelligence directly to persistent JSON storage.

## 💻 Tech Stack
- **Language:** Python 3.x
- **Advanced Concepts:** Custom Functions (`def`), Return values, Main Execution Block Control (`__main__`), CSV & JSON I/O Modules.

# Cyber Security Log Analyzer 🛡️

A lightweight Python-based security script that simulates a SIEM (Security Information and Event Management) system parser to analyze authentication logs and detect potential brute-force attacks.

## ✨ Features
- **Dynamic Event Parsing:** Processes a list of dictionary-based security events (20 simulated login events).
- **Logon Counter:** Tracks and aggregates failed login attempts per user dynamically using Python dictionaries.
- **Protocol Tracking:** Identifies authentication protocols such as SSH, RDP, and HTTPS.
- **Clean Output:** Generates a structured security report highlighting the total number of failed logons for system administrators.

## 🚀 How It Works
The script iterates through a centralized collection of network logon events, extracts critical keys (`User`, `IP`, `Protocol`, `Status`), and maintains a real-time counter for anomalies. If a user accumulates multiple failed attempts, it flags them as a potential security risk.

## 📂 Source Code
You can check out the source code directly here: [log_analyzer.py](log_analyzer.py)

## 💻 Tech Stack
- **Language:** Python 3.x
- **Concepts Used:** Variables, Strings, Lists, Dictionaries, Conditional Logic (`if/else`), Loops.

"""
===================================================================
PROJECT: Cyber Security Log Analyzer
AUTHOR: ASAD DAFALLA / Noxen
VERSION: 2.0.0 (Modular / Functions Update)
NOTE: This update structures the log analyzer into reusable
      functions using parameters and arguments.
===================================================================
"""

import csv
import json


# Function to Load Logs (Takes the file path as an argument)
def load_logs(file_path):
    logon_events = []
    with open(file_path, "r", newline="") as file_input:
        reader = csv.DictReader(file_input)
        for row in reader:
            logon_events.append(row)
    return logon_events  # Returns the list to whoever called the function


# Function to Analyze Security Logic (Takes the logs list as an argument)
def analyze_brute_force(logon_events):
    failed_login_counts = {}

    for event in logon_events:
        user_id = event["User"]
        status_id = event["Status"]

        if status_id == "Failed":
            if user_id in failed_login_counts:
                failed_login_counts[user_id] += 1
            else:
                failed_login_counts[user_id] = 1

    return failed_login_counts  # Returns the finalized dictionary report


# Function to Export Results (Takes the data and target file path as arguments)
def export_report(report_data, output_path):
    with open(output_path, "w") as file_out:
        json.dump(report_data, file_out, indent=4)
    print(f"Success! Security report exported to '{output_path}'.")


# THE CENTRAL CONTROL (Main Execution Flow)
# This is where we call our functions and pass arguments to them
if __name__ == "__main__":
    # Step A: Load the raw CSV logs
    raw_logs = load_logs("IoC.csv")

    # Step B: Pass those logs into our security analyzer engine
    security_analysis = analyze_brute_force(raw_logs)

    # Step C: Export the final calculated counts into a JSON file
    export_report(security_analysis, "failed_report_1.json")

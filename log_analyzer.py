"""
===================================================================
PROJECT: Cyber Security Log Analyzer
AUTHOR: ASAD DAFALLA / Noxen
VERSION: 1.0.0 (Alpha / Prototype)
NOTE: This is a prototype version focused on dynamic event parsing.
      It is NOT the final production release. Future updates will
      include automated blocking mechanisms and persistent storage.
===================================================================
"""

# Hardcoded list simulating central network authentication logs (SIEM logs)
Login_Events = [
    {"User": "admin", "IP": "192.168.10.2", "Protocol": "SSH", "Status": "Failed"},
    {"User": "admin", "IP": "192.168.10.2", "Protocol": "SSH", "Status": "Failed"},
    {"User": "jdoe", "IP": "192.168.1.50", "Protocol": "HTTPS", "Status": "Success"},
    {"User": "admin", "IP": "192.168.10.2", "Protocol": "SSH", "Status": "Success"},
    {"User": "smith_v", "IP": "192.168.164.23", "Protocol": "RDP", "Status": "Failed"},
    {"User": "smith_v", "IP": "192.168.164.23", "Protocol": "RDP", "Status": "Failed"},
    {"User": "guest_user", "IP": "192.168.12.3", "Protocol": "FTP", "Status": "Failed"},
    {"User": "smith_v", "IP": "192.168.164.23", "Protocol": "RDP", "Status": "Success"},
    {"User": "jdoe", "IP": "192.168.1.51", "Protocol": "HTTPS", "Status": "Failed"},
    {"User": "admin", "IP": "10.0.0.5", "Protocol": "SSH", "Status": "Success"},
    {"User": "alice", "IP": "172.16.32.10", "Protocol": "SMB", "Status": "Success"},
    {"User": "guest_user", "IP": "192.168.12.3", "Protocol": "FTP", "Status": "Failed"},
    {"User": "guest_user", "IP": "192.168.12.3", "Protocol": "FTP", "Status": "Failed"},
    {"User": "bob", "IP": "10.0.0.12", "Protocol": "RDP", "Status": "Failed"},
    {"User": "jdoe", "IP": "192.168.1.50", "Protocol": "HTTPS", "Status": "Success"},
    {"User": "bob", "IP": "10.0.0.12", "Protocol": "RDP", "Status": "Success"},
    {"User": "db_admin", "IP": "192.168.103.26", "Protocol": "MySQL", "Status": "Failed"},
    {"User": "db_admin", "IP": "192.168.103.26", "Protocol": "MySQL", "Status": "Failed"},
    {"User": "alice", "IP": "172.16.32.10", "Protocol": "SMB", "Status": "Success"},
    {"User": "db_admin", "IP": "192.168.103.26", "Protocol": "MySQL", "Status": "Failed"}
]

# Dictionary to map and track the number of failed login attempts per user
failed_login_counts = {}

# Iterate through each security event dictionary inside the logs list
for event in Login_Events:
    # Extract string values from the dictionary keys for readability
    UserID = event["User"]
    IP_ID = event["IP"]
    Protocol_ID = event["Protocol"]
    Status_ID = event["Status"]

    # Filter only failed logon attempts to detect brute-force indicators
    if Status_ID == "Failed":
        # Increment counter if user already exists in our tracking dictionary
        if UserID in failed_login_counts:
            failed_login_counts[UserID] += 1
        # Initialize the user counter to 1 if it's their first failed attempt
        else:
            failed_login_counts[UserID] = 1

# Generate and print a clean security report for system administrators
for UserID, count in failed_login_counts.items():
    print(f"The User: {UserID} has {count} failed logons")

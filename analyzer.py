import re
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"IP=(?P<ip>\S+) USER=(?P<user>\S+) STATUS=(?P<status>FAILED|SUCCESS)$"
)


def analyze_logs(file_path, threshold=5, time_window=10):
    """Analyze authentication logs and flag IPs with repeated failed logins."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if time_window < 1:
        raise ValueError("time_window must be at least 1 minute")

    failed_attempts = defaultdict(list)
    successful_logins = []
    invalid_lines = 0
    total_lines = 0

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            match = LOG_PATTERN.match(line)
            if not match:
                invalid_lines += 1
                continue

            data = match.groupdict()

            try:
                ipaddress.ip_address(data["ip"])
                timestamp = datetime.strptime(
                    data["timestamp"], "%Y-%m-%d %H:%M:%S"
                )
            except ValueError:
                invalid_lines += 1
                continue

            if data["status"] == "FAILED":
                failed_attempts[data["ip"]].append(timestamp)
            else:
                successful_logins.append({
                    "timestamp": data["timestamp"],
                    "ip": data["ip"],
                    "user": data["user"],
                    "status": data["status"],
                })

    threats = []
    window = timedelta(minutes=time_window)

    for ip, timestamps in failed_attempts.items():
        timestamps.sort()
        left = 0

        for right, current_time in enumerate(timestamps):
            while current_time - timestamps[left] > window:
                left += 1

            attempts_in_window = right - left + 1
            if attempts_in_window >= threshold:
                threats.append({
                    "ip": ip,
                    "attempts": attempts_in_window,
                    "first_attempt": timestamps[left].strftime("%Y-%m-%d %H:%M:%S"),
                    "last_attempt": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "threat": "Possible Brute Force Attack",
                })
                break

    return {
        "total_lines": total_lines,
        "total_failed": sum(len(items) for items in failed_attempts.values()),
        "total_successful": len(successful_logins),
        "unique_failed_ips": len(failed_attempts),
        "invalid_lines": invalid_lines,
        "threats": threats,
        "successful_logins": successful_logins,
    }

import csv
import json


def generate_reports(results, output_dir="."):
    """Write analysis results to JSON and CSV files."""
    json_path = f"{output_dir}/security_report.json"
    csv_path = f"{output_dir}/security_report.csv"

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    fieldnames = [
        "ip",
        "attempts",
        "first_attempt",
        "last_attempt",
        "threat",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results["threats"])

    return json_path, csv_path

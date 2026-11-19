import argparse
from pathlib import Path

from analyzer import analyze_logs
from report import generate_reports


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for possible brute-force activity."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default="sample.log",
        help="Path to the log file (default: sample.log)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts needed to flag an IP (default: 5)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Time window in minutes (default: 10)",
    )
    parser.add_argument(
        "--output",
        default=".",
        help="Directory for generated reports (default: current directory)",
    )
    args = parser.parse_args()

    try:
        results = analyze_logs(
            args.log_file,
            threshold=args.threshold,
            time_window=args.window,
        )

        print("\\n" + "=" * 48)
        print("       PYTHON LOG THREAT ANALYZER")
        print("=" * 48)
        print(f"Total log lines:          {results['total_lines']}")
        print(f"Failed login attempts:    {results['total_failed']}")
        print(f"Successful logins:        {results['total_successful']}")
        print(f"Unique failed-login IPs:  {results['unique_failed_ips']}")
        print(f"Invalid log lines:        {results['invalid_lines']}")

        print("\\nTHREAT DETECTION")
        print("-" * 48)

        if results["threats"]:
            for threat in results["threats"]:
                print(f"IP address:    {threat['ip']}")
                print(f"Attempts:      {threat['attempts']}")
                print(f"Detection:     {threat['threat']}")
                print(f"First attempt: {threat['first_attempt']}")
                print(f"Last attempt:  {threat['last_attempt']}\\n")
        else:
            print("No brute-force patterns detected.")

        Path(args.output).mkdir(parents=True, exist_ok=True)
        json_path, csv_path = generate_reports(results, args.output)
        print("Reports generated:")
        print(f"- {json_path}")
        print(f"- {csv_path}")

    except FileNotFoundError:
        parser.error(f"Log file not found: {args.log_file}")
    except PermissionError:
        parser.error("Permission denied while reading or writing a file.")
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()

# Python Log Analyzer & Threat Detection System

A Python command-line tool that analyzes authentication logs, summarizes login activity, and flags IP addresses with repeated failed login attempts that may indicate brute-force activity.

## Features

- Parses timestamped authentication log entries.
- Validates IPv4 and IPv6 addresses.
- Counts successful and failed login attempts.
- Detects repeated failed logins within a configurable time window.
- Reports malformed or invalid log entries.
- Exports results as JSON and CSV.
- Uses only Python's standard library.

## Project structure

```text
Python-Log-Threat-Analyzer/
├── analyzer.py
├── main.py
├── report.py
├── sample.log
├── requirements.txt
├── README.md
└── .gitignore
```

## Requirements

- Python 3.9 or newer
- No third-party packages

## Run

From the project directory:

```bash
python main.py
```

By default, the program analyzes `sample.log`.

You can also provide another log file:

```bash
python main.py my_server.log
```

## Customize detection

The default threshold is 5 failed attempts within 10 minutes.

```bash
python main.py sample.log --threshold 5 --window 10
```

Choose an output directory:

```bash
python main.py sample.log --output reports
```

## Expected sample result

The included sample log contains six failed login attempts from `192.168.1.10` within six minutes. The tool should flag this address as a **Possible Brute Force Attack**.

## Log format

Each non-empty line must follow this format:

```text
YYYY-MM-DD HH:MM:SS IP=ADDRESS USER=USERNAME STATUS=FAILED
```

or:

```text
YYYY-MM-DD HH:MM:SS IP=ADDRESS USER=USERNAME STATUS=SUCCESS
```

## Output files

After analysis, the program creates:

- `security_report.json` — complete analysis results.
- `security_report.csv` — detected threat records.

## Important note

This is an educational defensive log-analysis project. A flagged pattern is an indicator for investigation, not proof of an attack. The tool analyzes only the log file supplied to it; it does not scan networks, access accounts, or block IP addresses.

## Future improvements

- Support additional server log formats.
- Add configurable detection rules.
- Build a dashboard for visualizing login activity.
- Add automated tests and threat trend analysis.

## License

This project is available under the MIT License.

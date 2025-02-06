## Logex - Log Monitoring & Alert System

A Python-based log monitoring and alert system designed to detect suspicious activity in system logs and send real-time alerts. Logex is configurable, extensible, and platform-independent, supporting both Linux and Windows systems.

### Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Configuration](#configuration)
  - [Starting Log Monitoring](#starting-log-monitoring)
  - [Realtime Monitoring](#realtime-monitoring)
  - [Dynamic Updates](#dynamic-updates)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

---

### Introduction

Logex is a comprehensive log monitoring and alert system designed to detect security breaches and anomalous behavior by continuously monitoring system log files for predefined patterns. This system is suitable for home users and organizations looking to secure their systems by detecting attacks as they happen.

---

### Features

*   **Real-time Log Monitoring:** Continuously monitors log files for new entries.
*   **Configurable Log Files:** Allows the user to specify which log files to monitor (supports Linux and Windows).
*   **Robust Pattern Matching:** Supports multiple regular expressions, `AND`, `OR`, `NOT` operators, and contextual matching for defining suspicious activity patterns.
*   **Multiple Match Types:** Supports `any` and `all` match types for more robust pattern matching.
*   **Flexible Alerting:** Supports alerts via email, console output, webhooks (e.g., Slack, Discord), and push notifications.
*   **Configurable Severity Levels:** Allows defining different alert methods for various severity levels (`high`, `medium`, `low`).
*   **Dynamic Configuration:** Allows updating the configuration in runtime by editing the configuration file without restarting the application.
*   **State Management:** Keeps track of the last read entry in each log file to avoid re-reading.
*  **Threaded Monitoring:** The monitoring is done in a separated thread, to allow the system to reload the config while it monitors the logs.
*   **Platform Independent:** Supports Linux and Windows systems using platform-specific system libraries.
*   **Comprehensive Error Handling:** Implements `try-except` blocks for error detection and clear logging.
*   **Maintainable Code:** Designed with classes to ensure a modular and maintainable structure.

---

### Installation

To use Logex locally, follow these steps:

#### 1. Clone the Repository

```bash
git clone https://github.com/CodeByKalvin/Logex.git
cd Logex
```

#### 2. Install Dependencies

Make sure you have **Python 3** installed. Install the required dependencies using `pip`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` should contain the following:
```txt
requests
watchdog
pywin32
```

---

### Usage

Once installed, you can run the application from the command line using:

```bash
python log_monitor.py
```

#### Configuration

1. **Create Config File**: To create the initial configuration file run the app using the `-c` flag:
    ```bash
    python log_monitor.py -c
    ```
    This will generate the `monitor_config.json` file.
2. **Edit the Configuration**: Customize the `monitor_config.json` file to match your environment and desired log monitoring. This file allows you to set:
    *   `log_files`: A list of paths to the log files you want to monitor.
    *   `patterns`: A list of rules defining suspicious activities:
        *   `name`: A reference name for the pattern.
        *   `regex`: A regular expression to identify the pattern. You can use commas to specify multiple regex patterns for the `all` match type.
        *   `severity`: A severity level for the pattern (`high`, `medium`, `low`).
        *   `alert_methods`: Alert methods (e.g., `email`, `console`, `webhook`, `push`).
        *   `match_type`:  `any` or `all` to match any or all regexes.
        *   `context`: For context-based matching (not yet implemented).
    *   `email`: Configure email alerts, including the `smtp_server`, `smtp_port`, `smtp_user`, `smtp_password`, `from_email`, and `to_email`.
    *   `webhook`: Configure webhook alerts, including the `url`, `headers`, and `payload`. The payload supports the `{{alert_message}}` placeholder.
    *   `push`: Configure push notification alerts, including the `api_url`, `api_key`, `device_tokens`, and `payload`. The payload supports the `{{alert_message}}` placeholder.
    * `severity_levels`: Allows you to specify the alert methods to be used based on the `severity`.
3. **State File**: The system keeps track of the last processed entries using the `monitor_state.json` file.

#### Starting Log Monitoring

To start the log monitoring system:

```bash
python log_monitor.py -s
```

#### Realtime Monitoring

The system will continuously monitor specified log files and, if a pattern is detected, sends alerts according to the configuration and severity of the event. The application keeps track of the last processed entry using a state file, to avoid re-reading old logs.

#### Dynamic Updates

The application supports dynamic configuration. Any changes to the configuration file `monitor_config.json` are detected by the system, and the configuration is reloaded automatically, without having to restart the application.

---

### Project Structure

```
logex/
│
├── log_monitor.py         # Main Python script for running the CLI app
├── README.md              # This README file
├── requirements.txt       # List of dependencies
└── monitor_config.json # Sample configuration file.
```

---

### Requirements

-   **Python 3.6 or higher**
-   **Pip** to install dependencies
-   Required Python libraries (in `requirements.txt`):
    -   `requests`: For HTTP calls to webhooks and push notifications.
    -   `watchdog`: To monitor config file changes for dynamic updates.
    -   `pywin32`: For accessing Windows Event Logs.

To install the dependencies:

```bash
pip install -r requirements.txt
```

---

### Contributing

Contributions are welcome! If you would like to help the development of this project, please feel free to submit pull requests or open an issue if you would like to report a bug or request a new feature.

#### Steps to Contribute:

1. Fork the repository.
2. Create a new branch for your feature (`git checkout -b feature-name`).
3. Make your changes.
4. Test your changes.
5. Commit your changes (`git commit -m 'Add some feature'`).
6. Push to your branch (`git push origin feature-name`).
7. Create a pull request.

---

### License

This project is open-source and available under the [MIT License](LICENSE).

---

### Future Improvements

- Add support for more contextual matching.
- Improve the testing suite with unit and integration tests.
- Add support for other types of system logs (like Docker logs).
- Develop a GUI for better user experience.

---

### Authors

-   **CodeByKalvin** - *Initial work* - [GitHub Profile](https://github.com/codebykalvin)


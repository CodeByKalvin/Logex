import os
import re
import time
import json
import logging
import argparse
import platform
import smtplib
from email.mime.text import MIMEText
import requests
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import uuid
import sys
from abc import ABC, abstractmethod

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

print("""
  _____   ___  ___
 / ___/  / _ \/ __|
| |    |  __/|__ \\
| |___ | |  |___/
 \____| |_|  (_)
       Logex
       CodebyKalvin
""")

# Configuration file name
CONFIG_FILE_NAME = "monitor_config.json"
STATE_FILE_NAME = "monitor_state.json"

class ConfigManager:
    """Handles loading, updating, and creating config files."""
    def __init__(self, config_file=CONFIG_FILE_NAME):
      """Initialize with the config file name"""
      logging.info(f"ConfigManager __init__ called")
      self.config_file = config_file
      self.config = self._load_config()

    def _load_config(self):
        """Loads the configuration file."""
        try:
          with open(self.config_file, 'r') as f:
            config = json.load(f)
            logging.info("Configuration loaded.")
            return config
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Error loading config file: {e}")
            return {}
        except Exception as e:
           logging.error(f"Unexpected error loading config file: {e}")
           return {}

    def create_default_config(self):
      """Creates a default config file."""
      default_config = {
            "log_files": [],
            "patterns": [
              {
                  "name":"Example Pattern",
                  "regex": ".*(error|fail|exception).*",
                  "severity": "high",
                  "alert_methods":["email", "console"],
                   "match_type":"any",
                   "context":None
              }
            ],
            "email": {
                "enabled": False,
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "smtp_user": "your_email@example.com",
                "smtp_password": "your_password",
                "from_email": "your_email@example.com",
                "to_email": ["alert_recipient@example.com"]
            },
            "webhook": {
                "enabled": False,
                "url": "https://your-webhook-url.com",
                "headers": {"Content-type": "application/json"},
               "payload": {"message": "Log monitoring alert! {{alert_message}}"}
            },
            "push": {
                "enabled":False,
                "api_url":"https://push-api.com",
                "api_key": "your_api_key",
                "device_tokens": ["token1", "token2"],
               "payload": {"title": "Log monitoring alert!", "body":"{{alert_message}}"}
            },
            "severity_levels":{
                 "high": ["email","console"],
                 "medium": ["webhook"],
                 "low":["push"]
                }
        }
      try:
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
                logging.info(f"Created default config at '{self.config_file}'")
      except Exception as e:
            logging.error(f"Error creating default config: {e}")

class ConfigFileChangeHandler(FileSystemEventHandler):
    """Handles changes to the configuration file."""
    def __init__(self, config_manager):
        """Initialize with the config manager."""
        self.config_manager = config_manager
    def on_modified(self, event):
       """Handles config file modification"""
       if event.src_path == self.config_manager.config_file:
           logging.info("Config file changed, reloading...")
           self.config_manager.config = self.config_manager._load_config()

class StateManager:
    """Manages the state of the log monitor."""
    def __init__(self, state_file=STATE_FILE_NAME):
       """Initialize with the state file name."""
       logging.info(f"StateManager __init__ called")
       self.state_file = state_file
       self.state = self._create_state()

    def _create_state(self):
       try:
         with open(self.state_file, 'w') as f:
            json.dump({},f)
         logging.info(f"Created new state file: {self.state_file}")
         return {}
       except Exception as e:
         logging.error(f"Error creating state file: {e}")
         return {}

    def save_state(self, state):
      """Saves the state to the state file."""
      try:
        with open(self.state_file, 'w') as f:
          json.dump(state, f, indent=4)
          logging.info("State saved.")
      except Exception as e:
        logging.error(f"Error saving state: {e}")

class LogMonitor(ABC):
    """Abstract base class for log monitoring."""
    def __init__(self, config_manager, state_manager):
        """Initialize with config and state managers."""
        self.config_manager = config_manager
        self.state_manager = state_manager

    @abstractmethod
    def monitor_logs(self):
       """Abstract method for monitor log files."""
       pass

    @abstractmethod
    def _process_log_entry(self, log_file_path, log_entry, log_index):
       """Abstract method for processing log entries."""
       pass
    def _check_for_patterns(self, log_entry):
        """Checks if a log entry matches any predefined patterns."""
        try:
           matched_patterns = []
           for pattern in self.config_manager.config.get("patterns", []):
                match_type = pattern.get("match_type","any")
                if match_type == "any":
                     if re.search(pattern.get("regex", ""), log_entry, re.IGNORECASE):
                        matched_patterns.append(pattern)
                elif match_type == "all":
                    match = True
                    for regex in pattern.get("regex", "").split(","):
                        if not re.search(regex.strip(), log_entry, re.IGNORECASE):
                           match = False
                           break
                    if match:
                       matched_patterns.append(pattern)
           return matched_patterns
        except Exception as e:
           logging.error(f"Error checking patterns: {e}")
           return []
    def _send_alert(self, log_file_path, log_entry, pattern):
        """Sends alerts for a log entry based on configured methods."""
        try:
            alert_methods = self.config_manager.config.get("severity_levels",{}).get(pattern.get("severity","medium"),[])
            if not alert_methods:
                logging.warning(f"No alert methods found for severity {pattern.get('severity', 'medium')}")
            logging.info(f"Sending alert for '{pattern.get('name')}' in '{log_file_path}'. Severity: '{pattern.get('severity')}'")
            alert_message = f"Alert: Suspicious activity detected in log file: {log_file_path} \n Pattern: {pattern.get('name','N/A')}\n Severity: {pattern.get('severity','N/A')} \n Log Entry: {log_entry}"
            if "console" in alert_methods:
              logging.warning(alert_message)
            if "email" in alert_methods and self.config_manager.config.get("email",{}).get("enabled"):
             self._send_email_alert(alert_message)
            if "webhook" in alert_methods and self.config_manager.config.get("webhook",{}).get("enabled"):
              self._send_webhook_alert(alert_message)
            if "push" in alert_methods and self.config_manager.config.get("push",{}).get("enabled"):
              self._send_push_alert(alert_message)
        except Exception as e:
            logging.error(f"Error sending alerts: {e}")
    def _send_email_alert(self, message):
        """Sends an alert via email."""
        try:
            email_config = self.config_manager.config.get("email",{})
            logging.info("Sending email alert...")
            msg = MIMEText(message)
            msg['Subject'] = "Log Monitoring Alert"
            msg['From'] = email_config.get("from_email", "default@email.com")
            msg['To'] = ", ".join(email_config.get("to_email",[]))

            with smtplib.SMTP(email_config.get("smtp_server","localhost"), email_config.get("smtp_port",25)) as server:
                server.starttls()
                server.login(email_config.get("smtp_user",""), email_config.get("smtp_password",""))
                server.sendmail(email_config.get("from_email",""), email_config.get("to_email",[]), msg.as_string())
            logging.info("Email alert sent.")
        except Exception as e:
            logging.error(f"Error sending email: {e}")
    def _send_webhook_alert(self, message):
        """Sends an alert via webhook."""
        try:
           webhook_config = self.config_manager.config.get("webhook", {})
           logging.info("Sending webhook alert...")
           payload = json.dumps(webhook_config.get("payload",{})).replace("{{alert_message}}",message)
           response = requests.post(webhook_config.get("url",""), headers=webhook_config.get("headers",{}), data = payload, timeout=5)
           response.raise_for_status()
           logging.info("Webhook alert sent.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error sending webhook: {e}")
    def _send_push_alert(self, message):
        """Sends an alert via push notifications."""
        try:
           push_config = self.config_manager.config.get("push", {})
           logging.info("Sending push notification...")
           payload = json.dumps(push_config.get("payload",{})).replace("{{alert_message}}",message)
           for token in push_config.get("device_tokens",[]):
                headers = {"Authorization":f"Bearer {push_config.get('api_key','')}"}
                data = json.dumps({"to":token,"notification":json.loads(payload)})
                response = requests.post(push_config.get("api_url",""),headers = headers, data=data, timeout=5)
                response.raise_for_status()
           logging.info("Push alert sent.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error sending push alert: {e}")

class LinuxLogMonitor(LogMonitor):
    """Linux Implementation for a log monitor"""
    def __init__(self, config_manager, state_manager):
        """Initialize with config and state managers."""
        super().__init__(config_manager, state_manager)
    def _process_log_entry(self, log_file_path, log_entry, log_index):
        """Processes a new log entry"""
        for pattern in self._check_for_patterns(log_entry):
           self._send_alert(log_file_path, log_entry, pattern)
    def monitor_logs(self):
        """Monitors log files for new entries."""
        logging.info("Starting log monitoring in Linux...")
        for log_file_path in self.config_manager.config.get("log_files",[]):
           if not log_file_path in self.state_manager.state:
               self.state_manager.state[log_file_path] = {"last_line":0}
           try:
                with open(log_file_path, 'r') as log_file:
                  log_file.seek(0, os.SEEK_END)
                  current_line = self.state_manager.state[log_file_path]["last_line"]
                  while True:
                       line = log_file.readline()
                       if not line:
                           time.sleep(1)
                           continue
                       current_line += 1
                       if current_line > self.state_manager.state[log_file_path]["last_line"]:
                           self._process_log_entry(log_file_path, line, current_line)
                       self.state_manager.state[log_file_path]["last_line"] = current_line
                       self.state_manager.save_state(self.state_manager.state)
           except FileNotFoundError:
                logging.error(f"Log file not found: '{log_file_path}'")
           except Exception as e:
                logging.error(f"Unexpected error: {e}")

class WindowsLogMonitor(LogMonitor):
   """Windows Implementation for a log monitor"""
   def __init__(self, config_manager, state_manager):
       """Initialize with config and state managers."""
       super().__init__(config_manager, state_manager)
   def _process_log_entry(self, log_file_path, log_entry, log_index):
       """Process a new log entry"""
       for pattern in self._check_for_patterns(log_entry):
            self._send_alert(log_file_path, log_entry, pattern)
   def monitor_logs(self):
      """Monitors Windows log files."""
      logging.info("Starting log monitoring in Windows...")
      import win32evtlog # pip install pywin32
      for log_file_path in self.config_manager.config.get("log_files", []):
        if not log_file_path in self.state_manager.state:
          self.state_manager.state[log_file_path] = {"last_record_number":0}
        try:
          log_handle = win32evtlog.OpenEventLog(None, log_file_path)
          flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
          while True:
            events = win32evtlog.ReadEventLog(log_handle, flags, self.state_manager.state[log_file_path]["last_record_number"])
            if not events:
                time.sleep(1)
                continue
            for event in events:
                record_number = event.RecordNumber
                self.state_manager.state[log_file_path]["last_record_number"] = record_number
                formatted_log = str(event.StringInserts)
                self._process_log_entry(log_file_path, formatted_log, record_number)
            self.state_manager.save_state(self.state_manager.state)
        except Exception as e:
           logging.error(f"Error accessing windows event logs: {e}")

def create_log_monitor(config_manager, state_manager):
    """Creates a log monitor instance based on the OS."""
    system = platform.system()
    if system == "Windows":
      return WindowsLogMonitor(config_manager, state_manager)
    elif system == "Linux":
      return LinuxLogMonitor(config_manager, state_manager)
    else:
      logging.error(f"Unsupported system: {system}")
      return None

def main():
    """Main entry point of the application"""
    logging.info("main function called")
    parser = argparse.ArgumentParser(description="Log Monitoring and Alert System")
    parser.add_argument("-c", "--create_config", action="store_true", help="Create a config file.")
    parser.add_argument("-s", "--start", action="store_true", help="Start log monitoring.")
    args = parser.parse_args()

    config_manager = ConfigManager()
    state_manager = StateManager()

    if args.create_config:
        config_manager.create_default_config()
    elif config_manager.config:
      monitor = create_log_monitor(config_manager, state_manager)
      if monitor:
          if args.start:
            # Start monitoring in a separate thread
            thread = threading.Thread(target=monitor.monitor_logs)
            thread.daemon = True
            thread.start()
            # Watch for configuration file changes
            event_handler = ConfigFileChangeHandler(config_manager)
            observer = Observer()
            observer.schedule(event_handler, path='.', recursive=False)
            observer.start()
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                observer.stop()
                logging.info("Stopping log monitor...")
            observer.join()
          else:
            print("Use -s to start monitoring.")
      else:
           logging.error("Could not create monitor for the current OS.")
    else:
        logging.error("No configuration file found. Use -c to create one.")

if __name__ == "__main__":
    main()

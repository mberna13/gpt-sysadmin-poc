#!/usr/bin/env python3
import os
import re
import json
import subprocess
from datetime import datetime
from collections import defaultdict

# ANSI color codes
GREEN = "\033[92m"  # Bright green
RESET = "\033[0m"  # Reset to default color
RED = "\033[91m"  # Bright red
LIGHT_BLUE = "\033[94m"  # Bright blue
ORANGE_APPROX = "\033[93m"
ORANGE_256 = "\033[38;5;208m"

# ------------------------------------------------------------------------------
# Import the Google Generative AI client library for Gemini 2.0 Flash Exp.
import google.generativeai as genai

# Configure with your API key for Gemini 2.0
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

# ------------------------------------------------------------------------------
# Generate a log filename that includes date & time, stored in logs/ directory.
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)  # Create logs/ if it doesn't exist

TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')  # e.g., 20250113_213045
LOG_FILE = os.path.join(LOG_DIR, f"llm_admin_poc_{TIMESTAMP}.log")


# ------------------------------------------------------------------------------
# Logging setup
def log(message):
    """
    Write log messages to both a file and standard output with a timestamp.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"Failed to write to log file: {e}")


# ------------------------------------------------------------------------------
def progress_bar(current, total, bar_length=30):
    """
    Prints a block-style progress bar in the format:
    Progress: |██████----------| 40.0%
    'current' is the sub-step number completed, and 'total' is the total sub-steps.
    """
    if total <= 0:
        return  # Avoid division by zero

    percent = current / total
    filled_length = int(bar_length * percent)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\rProgress: |{bar}| {percent:.1%}', end='', flush=True)

    if current >= total:
        print()  # Move to a new line once finished


# ------------------------------------------------------------------------------
def summarize_auth_logs(raw_logs):
    """
    Parse auth logs to summarize failed SSH attempts and closed connections for root.
    """
    failed_password_pattern = r"Failed password for .* from ([\d\.]+)"
    closed_conn_pattern = r"Connection closed by authenticating user root\s+([\d\.]+)\s+port"

    activity = []

    failed_ips = re.findall(failed_password_pattern, raw_logs)
    for ip in failed_ips:
        activity.append(("Failed", ip))

    closed_ips = re.findall(closed_conn_pattern, raw_logs)
    for ip in closed_ips:
        activity.append(("Closed", ip))

    if not activity:
        return ("No failed SSH login attempts or repeated 'connection closed' lines "
                "for root found in the last logs.")

    suspicious_dict = defaultdict(lambda: {"Failed": 0, "Closed": 0})
    for reason, ip in activity:
        suspicious_dict[ip][reason] += 1

    summary_lines = []
    for ip, counts in suspicious_dict.items():
        f_count = counts["Failed"]
        c_count = counts["Closed"]
        line = (f"IP {ip} -> {f_count} 'Failed password' event(s), "
                f"{c_count} 'connection closed' event(s) for root.")
        summary_lines.append(line)

    summary_text = "\n".join(summary_lines)
    return "Potentially suspicious SSH events:\n" + summary_text


# ------------------------------------------------------------------------------
def get_log_maintenance_summary():
    """
    Count the number of log files in /var/log older than 30 days.
    """
    cmd = "find /var/log -type f -mtime +30 2>/dev/null | wc -l"
    result = subprocess.getoutput(cmd)
    try:
        old_logs_count = int(result)
    except ValueError:
        old_logs_count = 0

    if old_logs_count == 0:
        return "No log files older than 30 days were found in /var/log."
    else:
        return f"{old_logs_count} log files older than 30 days exist in /var/log (consider removing or archiving)."


# ------------------------------------------------------------------------------
def get_cpu_mem_info():
    """
    Retrieve CPU load and memory usage.
    """
    try:
        uptime_out = subprocess.getoutput("uptime")
    except Exception as e:
        uptime_out = f"Error retrieving uptime: {e}"
    try:
        free_out = subprocess.getoutput("free -m")
    except Exception as e:
        free_out = f"Error retrieving memory info: {e}"
    return f"CPU/Load Info:\n{uptime_out}\n\nMemory Usage (MB):\n{free_out}"


# ------------------------------------------------------------------------------
def get_io_info():
    """
    Retrieve I/O statistics.
    """
    try:
        iostat_out = subprocess.getoutput("iostat -x 1 1 2>/dev/null || echo 'iostat not available.'")
    except Exception as e:
        iostat_out = f"Error retrieving I/O stats: {e}"
    return f"I/O Stats:\n{iostat_out}"


# ------------------------------------------------------------------------------
def get_service_health():
    """
    Check for failed systemd services.
    """
    try:
        services_out = subprocess.getoutput("systemctl --failed 2>/dev/null")
    except Exception as e:
        services_out = f"Error retrieving service health: {e}"
    if "0 loaded units listed" in services_out:
        return "No failed systemd services."
    else:
        return f"Some systemd services are failing:\n{services_out}"


# ------------------------------------------------------------------------------
def check_rootkits():
    """
    Run a rootkit check using rkhunter if installed.
    """
    try:
        rkhunter_out = subprocess.getoutput("rkhunter --version 2>/dev/null")
    except Exception as e:
        return f"Error checking rkhunter version: {e}"
    if "Rootkit Hunter" not in rkhunter_out:
        return "rkhunter not installed or unavailable. No rootkit check performed."

    try:
        check_out = subprocess.getoutput("sudo rkhunter --check --sk --nocolors 2>/dev/null")
    except Exception as e:
        return f"Error running rkhunter check: {e}"
    summary_lines = []
    capture = False
    for line in check_out.splitlines():
        if "System checks summary" in line:
            capture = True
        if capture:
            summary_lines.append(line)
    if summary_lines:
        return "\n".join(summary_lines)
    else:
        return "Ran rkhunter check but could not parse a summary. Check logs manually."


# ------------------------------------------------------------------------------
def check_apache_access_log(log_path="/var/log/apache2/access.log", num_lines=200):
    """
    Check the last `num_lines` lines of the Apache access log for suspicious requests
    (e.g., wp-login.php, wp-admin, phpmyadmin, or /pma).
    """
    if not os.path.exists(log_path):
        return f"Apache access log not found at {log_path}."

    try:
        access_data = subprocess.getoutput(f"tail -n {num_lines} {log_path}")
    except Exception as e:
        return f"Error reading Apache log: {e}"

    suspicious_patterns = [
        r"wp-login\.php",
        r"wp-admin",
        r"phpmyadmin",
        r"/pma",
    ]

    suspicious_ips = defaultdict(int)
    lines = access_data.splitlines()
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        for pattern in suspicious_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                suspicious_ips[ip] += 1
                break

    if not suspicious_ips:
        return f"No suspicious WP/phpMyAdmin activity in the last {num_lines} lines."

    summary_lines = [f"Suspicious requests found in the last {num_lines} lines of Apache access log:"]
    for ip, count in suspicious_ips.items():
        summary_lines.append(f"  IP {ip} -> {count} suspicious request(s).")

    return "\n".join(summary_lines)


# ------------------------------------------------------------------------------
def get_system_info():
    """
    Gather system info with a progress bar showing these sub-steps:
      1. apt updates
      2. CPU/memory info
      3. I/O stats
      4. systemd services health
      5. log maintenance summary
      6. rootkit detection summary
      7. syslog snippet (last 10 lines)
      8. auth log snippet (last 200 lines)
      9. disk usage
     10. Apache access log summary
    """
    log("Gathering extended system information...")

    total_steps = 10
    current_step = 0
    progress_bar(current_step, total_steps)

    # 1. Basic updates info
    apt_list = subprocess.getoutput("apt list --upgradable 2>/dev/null")
    current_step += 1
    progress_bar(current_step, total_steps)

    # 2. CPU & Memory info
    cpu_mem_summary = get_cpu_mem_info()
    current_step += 1
    progress_bar(current_step, total_steps)

    # 3. I/O stats
    io_summary = get_io_info()
    current_step += 1
    progress_bar(current_step, total_steps)

    # 4. Service health
    service_summary = get_service_health()
    current_step += 1
    progress_bar(current_step, total_steps)

    # 5. Log maintenance
    log_maint_summary = get_log_maintenance_summary()
    current_step += 1
    progress_bar(current_step, total_steps)

    # 6. Rootkit check
    rootkit_summary = check_rootkits()
    current_step += 1
    progress_bar(current_step, total_steps)

    # 7. Syslog snippet (last 10 lines)
    syslog_path = "/var/log/syslog"
    if os.path.exists(syslog_path):
        syslog_tail = subprocess.getoutput(f"tail -n 10 {syslog_path}")
    else:
        syslog_tail = f"Syslog file not found at {syslog_path}."
    current_step += 1
    progress_bar(current_step, total_steps)

    # 8. Auth log snippet (last 200 lines)
    auth_log_path = "/var/log/auth.log"
    if os.path.exists(auth_log_path):
        auth_logs_raw = subprocess.getoutput(f"tail -n 200 {auth_log_path}")
    else:
        auth_logs_raw = f"Auth log file not found at {auth_log_path}."
    auth_logs_summary = summarize_auth_logs(auth_logs_raw)
    current_step += 1
    progress_bar(current_step, total_steps)

    # 9. Disk usage
    df_out = subprocess.getoutput("df -h")
    current_step += 1
    progress_bar(current_step, total_steps)

    # 10. Apache access log summary
    apache_access_log_summary = check_apache_access_log()
    current_step += 1
    progress_bar(current_step, total_steps)

    system_info = f"""
== PACKAGE UPDATES ==
{apt_list}

== CPU/MEM INFO ==
{cpu_mem_summary}

== I/O INFO ==
{io_summary}

== SERVICE HEALTH ==
{service_summary}

== LOG MAINTENANCE ==
{log_maint_summary}

== ROOTKIT DETECTION ==
{rootkit_summary}

== SYSLOG (last 10 lines) ==
{syslog_tail}

== AUTH LOG SUMMARY (last 200 lines) ==
{auth_logs_summary}

== DISK USAGE ==
{df_out}

== APACHE ACCESS LOG SUMMARY ==
{apache_access_log_summary}
    """

    log("Done gathering system information.")
    return system_info.strip()


# ------------------------------------------------------------------------------
def load_prompt_addons(path="prompt_suggestions.json"):
    """
    Reads a JSON file that supplements the internal prompts.
    Expected format:
    {
      "system_instructions": ["Extra system instruction 1", ...],
      "user_instructions": ["Extra user instruction 1", ...]
    }
    Returns a tuple: (list_of_system_instructions, list_of_user_instructions).
    """
    if not os.path.exists(path):
        log(f"No extra prompt file found at {path}; returning empty instructions.")
        return [], []

    try:
        with open(path, "r") as f:
            data = json.load(f)
        system_lines = data.get("system_instructions", [])
        user_lines = data.get("user_instructions", [])
        log(f"Loaded {len(system_lines)} system instructions and {len(user_lines)} user instructions from {path}.")
        return system_lines, user_lines
    except Exception as e:
        log(f"Error loading {path}: {e}")
        return [], []


# ------------------------------------------------------------------------------
def build_chat_messages(system_info, extra_system, extra_user):
    """
    Build chat-style messages for the Gemini 2.0 Flash Exp model,
    incorporating extra instructions from an external JSON file.
    """
    system_message_content = (
        "You are a thorough AI Linux system administrator assistant.\n"
        "Your goal is to keep the Ubuntu system secure, stable, and up-to-date.\n"
        "Analyze the provided system state, which includes:\n"
        " - Package updates (if any)\n"
        " - CPU/Memory usage (feel free to kill processes using too many resources)\n"
        " - Disk I/O stats\n"
        " - System services health\n"
        " - Log maintenance potential\n"
        " - Rootkit detection summary\n"
        " - Syslog snippet\n"
        " - SSH auth log summary for failed brute force login attempts (block these using iptables)\n"
        " - Disk usage (delete old files if nearly full)\n"
        " - Apache access log summary for potential exploit attempts (e.g., WordPress and phpMyAdmin) "
        "(block the IPs using iptables)\n\n"
        "IMPORTANT: When proposing a command, put it on a separate line starting with 'COMMAND:'\n"
        "For example:\n"
        "COMMAND: sudo apt update\n\n"
        "NOTE: Avoid interactive commands like 'less' as this script is fully automated.\n"
        "NOTE: Only propose destructive commands if absolutely necessary.\n"
    )
    for line in extra_system:
        system_message_content += f"- {line}\n"

    system_message = {
        "role": "system",
        "content": system_message_content
    }

    user_message_content = (
        f"Here is the current system state:\n\n{system_info}\n\n"
        "Please propose any needed commands or actions. If nothing is needed, simply say so.\n"
        "This script will automatically execute any commands you propose, so please be cautious.\n"
        "NOTE: Do not propose destructive commands unless absolutely necessary.\n"
    )
    for line in extra_user:
        user_message_content += f"- {line}\n"

    user_message = {
        "role": "user",
        "content": user_message_content
    }

    return [system_message, user_message]


# ------------------------------------------------------------------------------
def call_llm_chat(messages):
    """
    Send the constructed messages to Gemini 2.0 Flash Exp and retrieve its response.

    Since the Gemini API does not natively support a multi-message chat protocol,
    we combine the messages into a single prompt.
    """
    log("Sending messages to Gemini 2.0 Flash Exp...")

    # Combine messages with role labels
    prompt = ""
    for msg in messages:
        if msg["role"] == "system":
            prompt += "SYSTEM:\n" + msg["content"] + "\n\n"
        elif msg["role"] == "user":
            prompt += "USER:\n" + msg["content"] + "\n\n"

    log(f"Combined prompt for Gemini:\n{prompt}\n---END PROMPT---")

    # Create the generation configuration (you can adjust parameters as needed)
    generation_config = {
        "temperature": 1,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 8192,
        "response_mime_type": "text/plain",
    }

    # Create the model and start a chat session
    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash-exp",
        generation_config=generation_config,
    )

    chat_session = model.start_chat(history=[])
    try:
        response = chat_session.send_message(prompt)
        log(f"Raw response from Gemini:\n{response}")
        # Assuming the response object has a 'text' attribute.
        text_response = response.text if hasattr(response, "text") else str(response)
        return text_response.strip()
    except Exception as e:
        error_msg = f"Error calling Gemini 2.0 Flash Exp: {e}"
        log(error_msg)
        return ""


# ------------------------------------------------------------------------------
def extract_commands(llm_response):
    """
    Parse the LLM response for lines starting with 'COMMAND:'.
    Returns a list of command strings without the prefix.
    """
    commands = []
    for line in llm_response.splitlines():
        line = line.strip()
        if line.startswith("COMMAND:"):
            cmd = line.replace("COMMAND:", "", 1).strip()
            commands.append(cmd)
    return commands


# ------------------------------------------------------------------------------
def run_commands(commands):
    """
    Execute all proposed commands.
    WARNING: This function runs commands without any whitelist checks.
    """
    executed = []
    for cmd in commands:
        lower_cmd = cmd.lower()

        # Append '-y' for apt upgrade if missing
        if lower_cmd.startswith("sudo apt upgrade") and "-y" not in lower_cmd:
            log(f"Appending '-y' to upgrade command: {cmd}")
            cmd += " -y"

        # Replace 'less' with 'cat' to avoid interactive paging
        if lower_cmd.startswith("sudo less /var/log/rkhunter.log"):
            log(f"Overriding 'less' with 'cat' to avoid blocking. (original: {cmd})")
            cmd = "sudo cat /var/log/rkhunter.log"

        log(f"EXECUTING: {cmd} (No Whitelist!)")
        try:
            subprocess.run(cmd, shell=True, check=True)
            log(f"{LIGHT_BLUE}Command succeeded:{RESET} {cmd}")
            executed.append(cmd)
        except subprocess.CalledProcessError as e:
            log(f"{RED}Command failed:{RESET} {cmd} with error: {e}")

    return executed


# ------------------------------------------------------------------------------
def main():
    log("Starting Gemini 2.0 Flash Exp admin PoC WITHOUT a whitelist (full LLM control).")

    # 1. Load extra instructions from the external JSON file.
    extra_system, extra_user = load_prompt_addons("prompt_suggestions.json")

    # 2. Gather system information (with progress bar).
    system_info = get_system_info()

    # 3. Build the chat prompt messages.
    messages = build_chat_messages(system_info, extra_system, extra_user)

    # 4. Call the LLM.
    llm_response = call_llm_chat(messages)

    # 5. Log the full LLM response.
    log("LLM Response:")
    log(llm_response)

    # 6. Extract any commands proposed by the LLM.
    proposed_commands = extract_commands(llm_response)
    if not proposed_commands:
        log("No commands proposed by the LLM.")
    else:
        log(f"Proposed commands from LLM: {proposed_commands}")

    # 7. Execute the proposed commands automatically (no whitelist).
    executed_cmds = run_commands(proposed_commands)

    if executed_cmds:
        log(f"Executed {len(executed_cmds)} commands from LLM suggestions.")
    else:
        log("No commands executed.")

    log("Gemini 2.0 Flash Exp admin PoC (no whitelist) run completed.\n")


# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main()

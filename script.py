#!/usr/bin/env python3

import os
import re
import subprocess
from datetime import datetime
from collections import Counter, defaultdict

# ------------------------------------------------------------------------------
# Instead of importing openai directly, we import the OpenAI client
try:
    from openai import OpenAI
except ImportError:
    raise ImportError(
        "It looks like you don't have the new OpenAI client library that provides `OpenAI()`. "
        "Ensure you've installed the correct version or are using the right environment."
    )

# ------------------------------------------------------------------------------
# Generate a daily log filename based on YYYYMMDD
TODAY = datetime.now().strftime('%Y%m%d')
LOG_FILE = f"llm_admin_poc_{TODAY}.log"

# ------------------------------------------------------------------------------
# Logging setup
def log(message):
    """
    Simple function to write log messages to both a file and standard output.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

# ------------------------------------------------------------------------------
# OpenAI API setup
API_KEY = os.getenv("OPENAI_API_KEY", "YOUR_OPENAI_API_KEY")
MODEL_NAME = "gpt-4o"  # Using GPT-4o as shown in your Playground

# Create the OpenAI client
client = OpenAI(api_key=API_KEY)

# ------------------------------------------------------------------------------
def summarize_auth_logs(raw_logs):
    """
    Parse auth.log lines for:
      1. 'Failed password for' (IP)
      2. 'Connection closed by authenticating user root <IP> port'
    Return a text summary describing suspicious attempts.
    """
    failed_password_pattern = r"Failed password for .* from ([\d\.]+)"
    closed_conn_pattern = r"Connection closed by authenticating user root\s+([\d\.]+)\s+port"

    activity = []

    # Match "Failed password" lines
    failed_ips = re.findall(failed_password_pattern, raw_logs)
    for ip in failed_ips:
        activity.append(("Failed", ip))

    # Match "Connection closed" lines for root
    closed_ips = re.findall(closed_conn_pattern, raw_logs)
    for ip in closed_ips:
        activity.append(("Closed", ip))

    if not activity:
        return (
            "No failed SSH login attempts or repeated 'connection closed' lines for root found in the last logs."
        )

    # Tally occurrences
    suspicious_dict = defaultdict(lambda: {"Failed": 0, "Closed": 0})
    for reason, ip in activity:
        suspicious_dict[ip][reason] += 1

    summary_lines = []
    for ip, counts in suspicious_dict.items():
        f_count = counts["Failed"]
        c_count = counts["Closed"]
        line = (
            f"IP {ip} -> {f_count} 'Failed password' event(s), "
            f"{c_count} 'connection closed' event(s) for root."
        )
        summary_lines.append(line)

    summary_text = "\n".join(summary_lines)
    return "Potentially suspicious SSH events:\n" + summary_text

# ------------------------------------------------------------------------------
def get_log_maintenance_summary():
    """
    Illustrative example of 'log maintenance':
    find log files older than 30 days under /var/log (just counting them).
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
    Gather CPU load and memory usage info (via 'uptime' and 'free -m').
    """
    uptime_out = subprocess.getoutput("uptime")
    free_out = subprocess.getoutput("free -m")
    return f"CPU/Load Info:\n{uptime_out}\n\nMemory Usage (MB):\n{free_out}"

# ------------------------------------------------------------------------------
def get_io_info():
    """
    Gather I/O stats (via 'iostat -x 1 1'), if sysstat is installed.
    """
    iostat_out = subprocess.getoutput("iostat -x 1 1 2>/dev/null || echo 'iostat not available.'")
    return f"I/O Stats:\n{iostat_out}"

# ------------------------------------------------------------------------------
def get_service_health():
    """
    Check for failed or inactive systemd services (via 'systemctl --failed').
    """
    services_out = subprocess.getoutput("systemctl --failed 2>/dev/null")
    if "0 loaded units listed" in services_out:
        return "No failed systemd services."
    else:
        return f"Some systemd services are failing:\n{services_out}"

# ------------------------------------------------------------------------------
def check_rootkits():
    """
    Example using rkhunter in 'check' mode.
    Typically requires: sudo apt-get install rkhunter
    """
    rkhunter_out = subprocess.getoutput("rkhunter --version 2>/dev/null")
    if "Rootkit Hunter" not in rkhunter_out:
        return "rkhunter not installed or unavailable. No rootkit check performed."

    check_out = subprocess.getoutput("sudo rkhunter --check --sk --nocolors 2>/dev/null")
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
def get_system_info():
    """
    Gather system info:
    - apt updates
    - CPU/mem
    - I/O
    - systemd services health
    - log maintenance
    - rootkit detection
    - last 10 lines syslog
    - summary of last 50 lines of auth.log
    """
    log("Gathering extended system information...")

    # 1. Basic updates info
    apt_list = subprocess.getoutput("apt list --upgradable 2>/dev/null")

    # 2. CPU & Mem
    cpu_mem_summary = get_cpu_mem_info()

    # 3. I/O stats
    io_summary = get_io_info()

    # 4. Service health
    service_summary = get_service_health()

    # 5. Log maintenance
    log_maint_summary = get_log_maintenance_summary()

    # 6. Rootkit check
    rootkit_summary = check_rootkits()

    # 7. Syslog snippet
    syslog_tail = subprocess.getoutput("tail -n 10 /var/log/syslog")

    # 8. Auth log snippet
    auth_logs_raw = subprocess.getoutput("tail -n 50 /var/log/auth.log")
    auth_logs_summary = summarize_auth_logs(auth_logs_raw)

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

    == AUTH LOG SUMMARY (last 50 lines) ==
    {auth_logs_summary}
    """
    return system_info.strip()

# ------------------------------------------------------------------------------
def build_chat_messages(system_info):
    """
    Build chat-style messages for GPT-4o.
    We'll instruct the LLM to interpret the extended system info
    and propose safe, minimal changes if needed.
    BUT we also instruct it to output commands that we can parse and run automatically.
    """
    system_message = {
        "role": "system",
        "content": (
            "You are a thorough AI Linux system administrator assistant.\n"
            "Your goal is to keep the Ubuntu system secure, stable, and up-to-date.\n"
            "Analyze the provided system state, which includes:\n"
            " - Package updates (if any)\n"
            " - CPU/Memory usage\n"
            " - Disk I/O stats\n"
            " - System services health\n"
            " - Log maintenance potential\n"
            " - Rootkit detection summary\n"
            " - Syslog snippet\n"
            " - SSH auth log summary\n\n"
            "IMPORTANT: When you propose a command, put it on a separate line starting with 'COMMAND:'\n"
            "for example:\n"
            "COMMAND: sudo apt update\n"
            "so we can parse it automatically.\n"
            "Only propose safe, best-practice commands."
        )
    }

    user_message = {
        "role": "user",
        "content": (
            f"Here is the current system state:\n\n{system_info}\n\n"
            "Please do the following:\n"
            "1. If updates or packages need to be installed, output each install or update command on its own line, "
            "prefixed with 'COMMAND:'.\n"
            "2. If logs should be rotated or removed, propose the exact commands. "
            "Again, each command on its own line prefixed with 'COMMAND:'.\n"
            "3. If any service needs restarting or enabling, output that as well.\n"
            "4. Summarize what you did or recommended at the end.\n"
            "If nothing is needed, say 'No action required.'\n"
            "Only propose commands if they are truly necessary."
        )
    }
    return [system_message, user_message]

# ------------------------------------------------------------------------------
def call_llm_chat(messages):
    """
    Call GPT-4o using client.chat.completions.create(). Return the assistant's reply text.
    """
    log("Sending messages to the LLM...")

    # Log each message for debugging
    for i, msg in enumerate(messages):
        log(f"Message {i} ({msg['role']}):\n{msg['content']}\n---END---")

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            response_format={"type": "text"},
            temperature=0.0,
            max_completion_tokens=1000,
            top_p=1,
            frequency_penalty=0,
            presence_penalty=0
        )

        # Log the raw ChatCompletion object
        log(f"Raw response from GPT-4o:\n{response}")

        # 'response' is a ChatCompletion object, not a dict
        choices = response.choices
        if not choices:
            log("No choices returned from the LLM.")
            return ""

        text_response = choices[0].message.content
        return text_response.strip()

    except Exception as e:
        error_msg = f"Error calling GPT-4o: {e}"
        log(error_msg)
        return ""

# ------------------------------------------------------------------------------
def extract_commands(llm_response):
    """
    Parse the LLM response for lines that start with 'COMMAND:'.
    We'll return a list of the commands minus the prefix.
    """
    commands = []
    for line in llm_response.splitlines():
        line = line.strip()
        if line.startswith("COMMAND:"):
            # e.g. "COMMAND: sudo apt update"
            cmd = line.replace("COMMAND:", "", 1).strip()
            commands.append(cmd)
    return commands

# ------------------------------------------------------------------------------
# We'll split our whitelisting approach into two parts:
# 1) A list of exact commands (for convenience).
# 2) A list of regex patterns for commands that have variables, like IP addresses.

STATIC_SAFE_COMMANDS = [
    "sudo apt update",
    "sudo apt upgrade",
    "sudo apt upgrade -y",
    "sudo apt install fail2ban",
    "sudo apt install rkhunter",
    "sudo rkhunter --update",
    "sudo rkhunter --checkall",
    "sudo less /var/log/rkhunter.log",
    "sudo systemctl restart",
    "sudo systemctl enable",
    "sudo apt-get update",
    "sudo apt-get upgrade",
    "logrotate",
    # ... add more as needed
]

# Regex pattern that allows iptables DROP for any IPv4 address:
#   e.g. "sudo iptables -A INPUT -s 123.45.67.89 -j DROP"
REGEX_SAFE_COMMANDS = [
    r"^sudo iptables -A INPUT -s ([0-9]{1,3}\.){3}[0-9]{1,3} -j DROP$"
]

def is_whitelisted(cmd):
    """
    Check if 'cmd' matches any known safe command or regex pattern.
    """
    cmd_stripped = cmd.strip()
    cmd_lower = cmd_stripped.lower()

    # 1. Check static commands (exact match in lowercase).
    for safe_cmd in STATIC_SAFE_COMMANDS:
        # We'll do an exact match ignoring case:
        # if we wanted a substring, we could do something else
        if cmd_lower == safe_cmd.lower():
            return True

    # 2. Check each regex in REGEX_SAFE_COMMANDS:
    for pattern in REGEX_SAFE_COMMANDS:
        if re.match(pattern, cmd_stripped):
            return True

    return False

# ------------------------------------------------------------------------------
def run_commands(commands):
    executed = []
    for cmd in commands:
        # If the LLM forgot -y on 'apt upgrade', force it
        lower_cmd = cmd.lower()
        if lower_cmd.startswith("sudo apt upgrade") and "-y" not in lower_cmd:
            log(f"Appending '-y' to upgrade command: {cmd}")
            cmd += " -y"

        # Now check if it's whitelisted (assuming you have a whitelist approach)
        if is_whitelisted(cmd):
            log(f"Executing whitelisted command: {cmd}")
            try:
                subprocess.run(cmd, shell=True, check=True)
                log(f"Command succeeded: {cmd}")
                executed.append(cmd)
            except subprocess.CalledProcessError as e:
                log(f"Command failed: {cmd} with error: {e}")
        else:
            log(f"NOT WHITELISTED, skipping: {cmd}")
    return executed

# ------------------------------------------------------------------------------
def main():
    log("Starting GPT-4o admin PoC with extended checks AND auto-execution...")

    # 1. Gather system info
    system_info = get_system_info()

    # 2. Build the chat prompt (with instructions for the LLM to produce "COMMAND:")
    messages = build_chat_messages(system_info)

    # 3. Call the LLM
    llm_response = call_llm_chat(messages)

    # 4. Log the LLM's entire output
    log("LLM Response:")
    log(llm_response)

    # 5. Extract any commands from lines starting with "COMMAND:"
    proposed_commands = extract_commands(llm_response)
    if not proposed_commands:
        log("No commands proposed by the LLM.")
    else:
        log(f"Proposed commands from LLM: {proposed_commands}")

    # 6. Execute whitelisted commands automatically
    executed_cmds = run_commands(proposed_commands)

    # 7. Summarize the results
    if executed_cmds:
        log(f"Executed {len(executed_cmds)} commands from LLM suggestions.")
    else:
        log("No commands executed.")

    log("GPT-4o admin PoC run completed.\n")

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
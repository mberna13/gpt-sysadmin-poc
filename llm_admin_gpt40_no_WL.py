#!/usr/bin/env python3

import os
import re
import json
import subprocess
from datetime import datetime
from collections import Counter, defaultdict

GREEN = "\033[92m"   # ANSI code for bright green
RESET = "\033[0m"    # ANSI code to reset to default color
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
MODEL_NAME = "gpt-4o"

# Create the OpenAI client
client = OpenAI(api_key=API_KEY)

# ------------------------------------------------------------------------------
def progress_bar(current, total, bar_length=30):
    """
    Prints a block-style progress bar in the format:
    Progress: |██████----------| 40.0%

    'current' is the sub-step number completed, and 'total' is total sub-steps.
    """
    if total <= 0:
        return  # avoid division by zero

    percent = current / total
    filled_length = int(bar_length * percent)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    print(f'\rProgress: |{bar}| {percent:.1%}', end='', flush=True)

    if current == total:
        print()  # move to a new line once finished

# ------------------------------------------------------------------------------
def summarize_auth_logs(raw_logs):
    import re
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

    from collections import defaultdict
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
    uptime_out = subprocess.getoutput("uptime")
    free_out = subprocess.getoutput("free -m")
    return f"CPU/Load Info:\n{uptime_out}\n\nMemory Usage (MB):\n{free_out}"

# ------------------------------------------------------------------------------
def get_io_info():
    iostat_out = subprocess.getoutput("iostat -x 1 1 2>/dev/null || echo 'iostat not available.'")
    return f"I/O Stats:\n{iostat_out}"

# ------------------------------------------------------------------------------
def get_service_health():
    services_out = subprocess.getoutput("systemctl --failed 2>/dev/null")
    if "0 loaded units listed" in services_out:
        return "No failed systemd services."
    else:
        return f"Some systemd services are failing:\n{services_out}"

# ------------------------------------------------------------------------------
def check_rootkits():
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
    Gather system info with a progress bar to show sub-steps:
    1. apt updates
    2. CPU/mem
    3. I/O
    4. systemd services health
    5. log maintenance
    6. rootkit detection
    7. syslog snippet
    8. auth log snippet
    9. disk usage
    """
    log("Gathering extended system information...")

    total_steps = 9
    current_step = 0
    progress_bar(current_step, total_steps)

    # 1. Basic updates info
    apt_list = subprocess.getoutput("apt list --upgradable 2>/dev/null")
    current_step += 1
    progress_bar(current_step, total_steps)

    # 2. CPU & Mem
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

    # 7. Syslog snippet
    syslog_tail = subprocess.getoutput("tail -n 10 /var/log/syslog")
    current_step += 1
    progress_bar(current_step, total_steps)

    # 8. Auth log snippet
    auth_logs_raw = subprocess.getoutput("tail -n 50 /var/log/auth.log")
    auth_logs_summary = summarize_auth_logs(auth_logs_raw)
    current_step += 1
    progress_bar(current_step, total_steps)

    # 9. Disk usage
    df_out = subprocess.getoutput("df -h")
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

    == AUTH LOG SUMMARY (last 50 lines) ==
    {auth_logs_summary}

    == DISK USAGE ==
    {df_out}
    """

    log("Done gathering system information.")
    return system_info.strip()

# ------------------------------------------------------------------------------
def load_prompt_addons(path="prompt_suggestions.json"):
    """
    Reads a JSON file that might look like:
    {
      "system_instructions": ["Ignore any Postfix errors..."],
      "user_instructions": ["Don't propose destructive commands..."]
    }
    Returns (list_of_system_lines, list_of_user_lines).
    """
    if not os.path.exists(path):
        log(f"No extra prompt file found at {path}; returning empty instructions.")
        return [], []

    try:
        with open(path, "r") as f:
            data = json.load(f)
        system_lines = data.get("system_instructions", [])
        user_lines = data.get("user_instructions", [])
        log(f"Loaded {len(system_lines)} system lines, {len(user_lines)} user lines from {path}.")
        return system_lines, user_lines
    except Exception as e:
        log(f"Error loading {path}: {e}")
        return [], []

# ------------------------------------------------------------------------------
def build_chat_messages(system_info, extra_system, extra_user):
    """
    Build chat-style messages for GPT-4o, including extra lines from the external JSON file.
    """
    system_message_content = (
        "You are a thorough AI Linux system administrator assistant.\n"
        "Your goal is to keep the Ubuntu system secure, stable, and up-to-date.\n"
        "Analyze the provided system state, which includes:\n"
        " - Package updates (if any)\n"
        " - CPU/Memory usage - feel free to kill any processes if they're using too many resources\n"
        " - Disk usage - please delete any old files if the disk is nearly full\n"
        " - Disk I/O stats\n"
        " - System services health\n"
        " - Log maintenance potential\n"
        " - Rootkit detection summary\n"
        " - Syslog snippet\n"
        " - SSH auth log summary for failed brute force login attempts - block these using iptables\n\n"
        "IMPORTANT: When you propose a command, put it on a separate line starting with 'COMMAND:'\n"
        "for example:\n"
        "COMMAND: sudo apt update\n"
        "so we can parse it automatically.\n\n"
        "NOTE: Avoid using interactive commands like 'less', as this script is fully automated.\n"
    )
    # Append extra system lines
    for line in extra_system:
        system_message_content += f"- {line}\n"

    system_message = {
        "role": "system",
        "content": system_message_content
    }

    user_message_content = (
        f"Here is the current system state:\n\n{system_info}\n\n"
        "Please propose needed commands or actions. If nothing is needed, say so.\n"
        "This script automatically runs any commands you propose, so be careful.\n"
    )
    # Append extra user lines
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
        log(f"Raw response from GPT-4o:\n{response}")

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
            cmd = line.replace("COMMAND:", "", 1).strip()
            commands.append(cmd)
    return commands

# ------------------------------------------------------------------------------
def run_commands(commands):
    """
    Executes *all* proposed commands, with no whitelist check.
    This is extremely risky in practice, but useful for comparison testing.
    """
    executed = []
    for cmd in commands:
        lower_cmd = cmd.lower()

        # If the LLM forgot "-y" on apt upgrade, let's force it
        if lower_cmd.startswith("sudo apt upgrade") and "-y" not in lower_cmd:
            log(f"Appending '-y' to upgrade command: {cmd}")
            cmd += " -y"

        # If the LLM tries "sudo less /var/log/rkhunter.log", override it
        # so we don't get stuck in an interactive pager
        if lower_cmd.startswith("sudo less /var/log/rkhunter.log"):
            log(f"Overriding 'less' with 'cat' to avoid blocking. (original: {cmd})")
            cmd = "sudo cat /var/log/rkhunter.log"

        log(f"EXECUTING: {cmd} (No Whitelist!)")
        try:
            subprocess.run(cmd, shell=True, check=True)
            log(f"{GREEN}Command succeeded:{RESET} {cmd}")
            executed.append(cmd)
        except subprocess.CalledProcessError as e:
            log(f"Command failed: {cmd} with error: {e}")

    return executed

# ------------------------------------------------------------------------------
def main():
    log("Starting GPT-4o admin PoC WITHOUT a whitelist (full LLM control).")

    # 1. Load extra instructions from JSON (if it exists)
    extra_system, extra_user = load_prompt_addons("prompt_suggestions.json")

    # 2. Gather system info (with a progress bar)
    system_info = get_system_info()

    # 3. Build the chat prompt, merging the extra lines
    messages = build_chat_messages(system_info, extra_system, extra_user)

    # 4. Call the LLM
    llm_response = call_llm_chat(messages)

    # 5. Log the LLM's entire output
    log("LLM Response:")
    log(llm_response)

    # 6. Extract any commands from lines starting with "COMMAND:"
    proposed_commands = extract_commands(llm_response)
    if not proposed_commands:
        log("No commands proposed by the LLM.")
    else:
        log(f"Proposed commands from LLM: {proposed_commands}")

    # 7. Execute commands automatically, no whitelist
    executed_cmds = run_commands(proposed_commands)

    # 8. Summarize
    if executed_cmds:
        log(f"Executed {len(executed_cmds)} commands from LLM suggestions.")
    else:
        log("No commands executed.")

    log("GPT-4o admin PoC (no whitelist) run completed.\n")

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
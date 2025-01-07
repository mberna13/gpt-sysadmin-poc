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
# Logging setup
LOG_FILE = "llm_admin_gpt4.log"
def log(message):
    """
    Simple function to write log messages to both a file and standard output.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] {message}"
    print(log_line)
    with open(LOG_FILE, "a") as f:
        f.write(log_line + "\n")

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
    # Updated pattern to match your actual logs:
    closed_conn_pattern = r"Connection closed by authenticating user root\s+([\d\.]+)\s+port"

    activity = []

    # Match "Failed password" lines
    failed_ips = re.findall(failed_password_pattern, raw_logs)
    for ip in failed_ips:
        activity.append(("Failed", ip))

    # Match "Connection closed by ... user root" lines
    closed_ips = re.findall(closed_conn_pattern, raw_logs)
    for ip in closed_ips:
        activity.append(("Closed", ip))

    if not activity:
        return (
            "No failed SSH login attempts or repeated 'connection closed' lines for root found in the last logs."
        )

    # Tally occurrences by IP
    suspicious_dict = defaultdict(lambda: {"Failed": 0, "Closed": 0})

    for reason, ip in activity:
        suspicious_dict[ip][reason] += 1

    summary_lines = []
    for ip, counts in suspicious_dict.items():
        f_count = counts["Failed"]
        c_count = counts["Closed"]
        # Only mention IP if it has at least 1 event
        line = (f"IP {ip} -> {f_count} 'Failed password' event(s), "
                f"{c_count} 'connection closed' event(s) for root.")
        summary_lines.append(line)

    summary_text = "\n".join(summary_lines)
    return (
        "Potentially suspicious SSH events:\n" + summary_text
    )

# ------------------------------------------------------------------------------
def get_system_info():
    """
    Gather system info:
    - apt updates
    - disk usage
    - last 10 lines syslog
    - summary of last 50 lines of auth.log
    """
    log("Gathering system information...")

    apt_list = subprocess.getoutput("apt list --upgradable 2>/dev/null")
    disk_usage = subprocess.getoutput("df -h")
    syslog_tail = subprocess.getoutput("tail -n 10 /var/log/syslog")

    # Adjust the number of lines if needed
    auth_logs_raw = subprocess.getoutput("tail -n 50 /var/log/auth.log")
    auth_logs_summary = summarize_auth_logs(auth_logs_raw)

    system_info = f"""
    Packages needing updates (apt):
    {apt_list}

    Disk usage (df -h):
    {disk_usage}

    Last 10 lines of /var/log/syslog:
    {syslog_tail}

    Auth log summary (last 50 lines):
    {auth_logs_summary}
    """
    return system_info.strip()

# ------------------------------------------------------------------------------
def build_chat_messages(system_info):
    """
    Build chat-style messages for GPT-4o. We'll use a system message to define its role,
    and a user message to provide the 'system state' context.
    """
    system_message = {
        "role": "system",
        "content": (
            "You are a helpful AI Linux system administrator assistant.\n"
            "Your goal is to keep the Ubuntu system secure, stable, and up-to-date.\n"
            "If the apt upgradeable package list is empty, do NOT recommend running apt updates.\n"
            "Analyze disk usage to determine if any immediate action is necessary.\n"
            "Determine if there are any abnormal issues present in the system log (/var/log/syslog).\n"
            "You also look for possible brute-force SSH login attempts or suspicious activity, "
            "including repeated 'connection closed' events for root from the same IP.\n"
            "You are cautious about risky changes and will only propose safe, best-practice commands.\n"
        )
    }

    user_message = {
        "role": "user",
        "content": (
            f"Here is the current system state:\n\n{system_info}\n\n"
            "Please:\n"
            "1. Propose any needed commands or actions to keep the system updated, if any.\n"
            "2. Propose any action needed based on disk usage, if any.\n"
            "3. Recommend any actions necessary based on system log output.\n"
            "4. Analyze the SSH auth log summary for suspicious activity (failed logins, brute force attempts,\n"
            "   repeated closed connections for root from the same IP, etc.).\n"
            "5. Provide security recommendations or commands to mitigate brute-force attacks, "
            "   but only if they appear in the logs.\n"
            "If none of the above is needed, explicitly say no action is required."
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
            max_completion_tokens=700,  # More tokens to allow a thorough response
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
def parse_llm_response(text_response):
    """
    For this PoC, we simply log the raw response text.
    """
    log("LLM Response:")
    log(text_response)
    return text_response

# ------------------------------------------------------------------------------
def main():
    log("Starting GPT-4o admin PoC...")

    system_info = get_system_info()
    messages = build_chat_messages(system_info)
    llm_response = call_llm_chat(messages)

    parse_llm_response(llm_response)

    log("GPT-4o admin PoC run completed.\n")

# ------------------------------------------------------------------------------
if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import os
import subprocess
from datetime import datetime

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
def get_system_info():
    """
    Gather basic system info:
    - apt updates available
    - disk usage
    - last 5 syslog lines
    """
    log("Gathering system information...")

    apt_list = subprocess.getoutput("apt list --upgradable 2>/dev/null")
    disk_usage = subprocess.getoutput("df -h")
    logs = subprocess.getoutput("tail -n 5 /var/log/syslog")

    system_info = f"""
    Packages needing updates (apt):
    {apt_list}

    Disk usage (df -h):
    {disk_usage}

    Last 5 lines of /var/log/syslog:
    {logs}
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
            "You are cautious about risky changes and will only propose safe commands.\n"
        )
    }

    user_message = {
        "role": "user",
        "content": (
            f"Here is the current system state:\n\n{system_info}\n\n"
            "Please propose any needed commands or actions. If none, explicitly say no action is required.\n"
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
        # This call matches the Playground code snippet for GPT-4o
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            response_format={"type": "text"},
            temperature=0.0,
            max_completion_tokens=400,
            top_p=1,
            frequency_penalty=0,
            presence_penalty=0
        )

        # Log the raw ChatCompletion object
        log(f"Raw response from GPT-4o:\n{response}")

        # response is a ChatCompletion object, not a dict
        choices = response.choices  # list of Choice objects

        if not choices:
            log("No choices returned from the LLM.")
            return ""

        # Extract the text from the first choice
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
    Later, you could parse out commands or instructions if you wish.
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

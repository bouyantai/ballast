"""
A minimal autonomous agent, used to demonstrate the Ballast proxy.

This agent does not import Ballast. It is included to show that an unmodified,
third-party agent can be audited by the proxy without code changes: only the
model URL is redirected, via an environment variable, as any agent already
supports.

    ollama run llama3.2                                   # start the model
    python3 proxy.py                                      # start the proxy (:8100)
    OLLAMA_HOST=localhost:8100 python3 agent.py "list the files here"

run_shell includes a small built-in allowlist so the demonstration cannot
affect the host. Enforcement of a third-party agent is a separate concern,
addressed by a future SDK adapter.
"""

import json
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.request

HOST = os.environ.get("OLLAMA_HOST", "localhost:11434")
OLLAMA_URL = f"http://{HOST}/api/chat"
MODEL = os.environ.get("AGENT_MODEL", "llama3.2")


# --- tools -----------------------------------------------------------------
def list_files(path="."):
    try:
        return "\n".join(sorted(os.listdir(path or "."))) or "(empty folder)"
    except Exception as e:
        return f"ERROR: {e}"


def read_file(path):
    try:
        with open(path) as f:
            return f.read()[:800]
    except Exception as e:
        return f"ERROR: {e}"


_DEMO_SAFE = {"ls", "pwd", "cat", "head", "tail", "wc", "find", "echo", "grep", "file", "stat", "date"}


def run_shell(command):
    # demonstration-only allowlist so this agent cannot affect the host
    if any(b in command.lower() for b in ("rm ", "sudo", "mv ", "dd ", ">", "|", ";", "curl", "wget", "-delete")):
        return "[demo blocked this command]"
    try:
        prog = shlex.split(command)[0]
    except (ValueError, IndexError):
        return "ERROR: could not parse command"
    if prog not in _DEMO_SAFE:
        return f"[demo blocked: '{prog}' not allowed]"
    try:
        out = subprocess.run(
            shlex.split(command), capture_output=True, text=True,
            timeout=5, stdin=subprocess.DEVNULL,
        )
        return (out.stdout + out.stderr).strip()[:800] or "(no output)"
    except Exception as e:
        return f"ERROR: {e}"


TOOLS = {"list_files": list_files, "read_file": read_file, "run_shell": run_shell}


# --- prompting -------------------------------------------------------------
SYSTEM = """You ARE able to act via real tools. NEVER say you cannot run things.
Every turn, output EXACTLY ONE line, no code fences:
  ACTION: tool_name | argument
  FINISH: <final answer>

Tools:
  list_files | <folder path>   lists files in a folder
  read_file  | <file path>     returns a file's contents
  run_shell  | <command>       runs a shell command and returns its output"""

ONE_SHOT = [
    {"role": "user", "content": "Goal: what files are here?"},
    {"role": "assistant", "content": "ACTION: list_files | ."},
    {"role": "user", "content": "Observation:\nnotes.txt\nmain.py"},
    {"role": "assistant", "content": "FINISH: There are 2 files: notes.txt and main.py."},
]


def ask_model(messages):
    body = json.dumps(
        {"model": MODEL, "messages": messages, "stream": False, "options": {"temperature": 0}}
    ).encode()
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())["message"]["content"].strip()
    except urllib.error.URLError:
        raise SystemExit(f"Could not reach the model at {OLLAMA_URL}.\nIs Ollama (or the proxy) running?")


def extract_command(reply):
    for raw in reply.splitlines():
        s = raw.strip().strip("`").strip()
        if s.upper().startswith(("ACTION:", "FINISH:")):
            return s
    return None


def run(goal, max_steps=6):
    messages = [{"role": "system", "content": SYSTEM}] + ONE_SHOT
    messages.append({"role": "user", "content": f"Goal: {goal}"})

    for step in range(1, max_steps + 1):
        reply = ask_model(messages)
        line = extract_command(reply)
        print(f"\n[step {step}] brain says -> {line or reply[:80] + ' ...(no command)'}")

        if line is None:
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": "One line only: ACTION: tool | arg  OR  FINISH: answer"})
            continue

        if line.upper().startswith("FINISH:"):
            print("\n[DONE]", line.split(":", 1)[1].strip())
            return

        _, _, rest = line.partition(":")
        name, _, arg = rest.partition("|")
        name, arg = name.strip(), arg.strip()

        tool = TOOLS.get(name)
        if tool is None:
            observation = f"ERROR: no tool named '{name}'"
        else:
            observation = tool(arg) if arg else tool()
        print(f"          hands did -> {name}({arg!r})")
        print(f"          result    -> {observation[:200].rstrip()}")

        messages.append({"role": "assistant", "content": line})
        messages.append({"role": "user", "content": f"Observation:\n{observation}"})

    print("\n[STOPPED] hit the step limit without finishing")


if __name__ == "__main__":
    goal = sys.argv[1] if len(sys.argv) > 1 else "List the files here and tell me what kind of project this is."
    run(goal)

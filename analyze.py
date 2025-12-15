#!/usr/bin/env python3
import os
import sys
import json
import re
from datetime import datetime
from typing import Any, Dict, Optional

from openai import OpenAI

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")


def load_env_file(path: str = ".env") -> None:
    """
    Minimal .env loader (KEY=VALUE, no export required).
    Does not override already-set environment variables.
    """
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v


def read_text(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().strip()


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_json_from_text(text: str) -> Dict[str, Any]:
    """
    Try to parse strict JSON. If the model wrapped extra text, recover the first JSON object.
    """
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not m:
            raise
        return json.loads(m.group(0))


SHELL_PROC_RE = re.compile(
    r'users:\(\("?(sh|bash|dash|zsh|ksh|python|python3|perl|ruby|php|nc|ncat|netcat|socat)"?',
    re.I
)


def detect_reverse_shell(facts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Deterministic IR gate:
    - If we have any established outbound connection owned by a shell-like process,
      treat as active compromise until disproven.
    """
    net = facts.get("network_activity", {})
    shell_like = (net.get("shell_like_outbound") or "").strip()
    established = (net.get("established_connections") or "").strip()

    if shell_like:
        return {
            "severity": "high",
            "category": "network",
            "evidence": shell_like,
            "reasoning": (
                "An established outbound network connection is owned directly by a shell or interpreter "
                "process (e.g., sh/bash/python/nc/socat). Interactive shells do not normally initiate or "
                "maintain persistent outbound TCP connections. The presence of active stdin/stdout file "
                "descriptors further aligns with reverse shell or live command-and-control tradecraft, "
                "making benign explanations unlikely without additional context."
            ),
            "recommended_next_step": (
                "1) Identify PID and parent: ps -fp <pid>; ps -o pid,ppid,user,etime,cmd -p <pid>\n"
                "2) Inspect process tree: pstree -asp <pid>\n"
                "3) Inspect /proc: readlink -f /proc/<pid>/exe; tr '\\0' ' ' < /proc/<pid>/cmdline\n"
                "4) Confirm remote endpoint: ss -tunp | grep <pid>\n"
                "5) Contain: isolate network or kill -STOP <pid> (preserve forensics), then acquire memory/disk"
            )
        }

    if established and SHELL_PROC_RE.search(established):
        return {
            "severity": "high",
            "category": "network",
            "evidence": established,
            "reasoning": (
                "Established outbound network traffic appears to be associated with a shell or interpreter "
                "process. Shell-owned network connections are atypical in normal system operation and are "
                "commonly associated with reverse shells or interactive command-and-control channels."
            ),
            "recommended_next_step": (
                "Extract PID from ss output and perform standard reverse-shell triage "
                "(process tree, /proc inspection, containment)."
            )
        }

    return None


def build_prompt(facts: Dict[str, Any], analyst_prompt_path: str = "analyst_prompt.txt") -> str:
    base = read_text(analyst_prompt_path)
    if not base:
        base = (
            "You are a senior Linux IR analyst. Output strictly JSON. "
            "Focus on suspicious activity, persistence, authentication, and live network indicators."
        )

    return (
        base
        + "\n\n"
        + "You will be given a JSON document of host telemetry. "
          "Pay special attention to network_activity.established_connections and "
          "network_activity.shell_like_outbound.\n"
        + f"Timestamp: {datetime.utcnow().isoformat()}Z\n"
    )


def main() -> int:
    load_env_file(".env")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <facts.json>", file=sys.stderr)
        return 2

    facts = load_json(sys.argv[1])

    forced = detect_reverse_shell(facts)

    client = OpenAI(
        api_key=os.getenv("OPENAI_API_KEY", ""),
        base_url=os.getenv("OPENAI_BASE_URL", None) or None
    )

    system_prompt = build_prompt(facts)
    user_content = json.dumps(facts, indent=2, ensure_ascii=False)

    resp = client.responses.create(
        model=DEFAULT_MODEL,
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    )

    text = (resp.output_text or "").strip()
    if not text:
        print("ERROR: Empty model response.", file=sys.stderr)
        return 1

    ai_out = extract_json_from_text(text)

    if "findings" not in ai_out or not isinstance(ai_out.get("findings"), list):
        ai_out["findings"] = []

    if forced:
        ai_out["findings"] = [forced] + ai_out["findings"]
        ai_out["overall_assessment"] = "likely_compromised"
        ai_out["confidence"] = max(float(ai_out.get("confidence", 0.0)), 0.90)

        ai_out.setdefault("verdict", {})
        if isinstance(ai_out["verdict"], dict):
            ai_out["verdict"]["suspicious"] = True
            ai_out["verdict"]["why"] = (
                "The system exhibits an active, established outbound TCP connection owned directly by a "
                "shell interpreter process. Shells do not normally maintain persistent network connections, "
                "particularly to non-standard ports, and the presence of interactive file descriptors "
                "strongly suggests remote interactive control. This pattern aligns closely with reverse "
                "shell or live command-and-control activity and should be treated as active compromise "
                "until a benign explanation is conclusively verified."
            )

        ai_out["findings"] = [
            f for f in ai_out["findings"] if f.get("category") != "network"
        ]
        ai_out["findings"].insert(0, forced)

    print(json.dumps(ai_out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

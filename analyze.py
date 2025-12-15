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
        # Recovery: find the first {...} block
        m = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not m:
            raise
        return json.loads(m.group(0))


SHELL_PROC_RE = re.compile(r'users:\(\("?(sh|bash|dash|zsh|ksh|python|python3|perl|ruby|php|nc|ncat|netcat|socat)"?', re.I)


def detect_reverse_shell(facts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Deterministic IR gate:
    - If we have any established outbound connection owned by a shell-like process,
      treat as active compromise until disproven.
    """
    net = facts.get("network_activity", {})
    shell_like = (net.get("shell_like_outbound") or "").strip()
    established = (net.get("established_connections") or "").strip()

    # Strong signal: explicit shell_like_outbound field populated
    if shell_like:
        evidence = shell_like
        return {
            "severity": "high",
            "category": "network",
            "evidence": evidence,
            "reasoning": (
                "Established outbound connection owned by an interactive shell/interpreter "
                "(sh/bash/python/nc/socat/etc). This matches reverse shell / live C2 tradecraft "
                "and should be treated as active compromise until disproven."
            ),
            "recommended_next_step": (
                "1) Identify PID and parent: ps -fp <pid>; ps -o pid,ppid,user,etime,cmd -p <pid>\n"
                "2) Inspect process tree: pstree -asp <pid>\n"
                "3) Inspect /proc: readlink -f /proc/<pid>/exe; tr '\\0' ' ' < /proc/<pid>/cmdline\n"
                "4) Confirm remote: ss -tunp | grep <pid>\n"
                "5) Contain: isolate network or kill -STOP <pid> (preserve forensics) then image if needed"
            )
        }

    # Backup: parse established_connections for shell-ish ownership if shell_like_outbound was empty
    if established and SHELL_PROC_RE.search(established):
        return {
            "severity": "high",
            "category": "network",
            "evidence": established,
            "reasoning": (
                "Established outbound connection appears to be owned by a shell/interpreter. "
                "Treat as probable reverse shell / live C2 until proven benign."
            ),
            "recommended_next_step": (
                "Extract PID from ss output and follow the same triage steps: ps/pstree/proc/containment."
            )
        }

    return None


def build_prompt(facts: Dict[str, Any], analyst_prompt_path: str = "analyst_prompt.txt") -> str:
    """
    We send the analyst prompt (from file) plus a compact instruction to focus on the data.
    """
    base = read_text(analyst_prompt_path)
    if not base:
        # Fallback (shouldn't happen in your repo, but safe)
        base = (
            "You are a senior Linux IR analyst. Output strictly JSON. "
            "Focus on suspicious activity, persistence, auth, live network."
        )

    # Important: ensure the model sees network_activity explicitly.
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

    facts_path = sys.argv[1]
    facts = load_json(facts_path)

    # Deterministic gate (before AI)
    forced = detect_reverse_shell(facts)

    client = OpenAI(
        api_key=os.getenv("OPENAI_API_KEY", ""),
        base_url=os.getenv("OPENAI_BASE_URL", None) or None
    )

    model = DEFAULT_MODEL

    system_prompt = build_prompt(facts)

    # Send the full facts JSON (not chunked) — your collector is already trimmed.
    user_content = json.dumps(facts, indent=2, ensure_ascii=False)

    # Call Responses API (no response_format param; your SDK rejected it)
    resp = client.responses.create(
        model=model,
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

    # Normalize output shape: your prompt should enforce these keys, but models can drift.
    # We'll preserve whatever it returned, but inject forced findings and override verdict if needed.
    if "findings" not in ai_out or not isinstance(ai_out.get("findings"), list):
        ai_out["findings"] = []

    # If forced reverse shell exists, insert it at top and override assessment fields if present.
    if forced:
        ai_out["findings"] = [forced] + ai_out["findings"]

        # Prefer your newer schema if present
        if "overall_assessment" in ai_out:
            ai_out["overall_assessment"] = "likely_compromised"
        else:
            # Backward compatible: add fields even if model didn't
            ai_out.setdefault("overall_assessment", "likely_compromised")

        # Confidence normalization
        if "confidence" in ai_out:
            try:
                # if 0-1 float
                if isinstance(ai_out["confidence"], (int, float)):
                    ai_out["confidence"] = max(float(ai_out["confidence"]), 0.90)
                # if 0-100 int
                elif isinstance(ai_out["confidence"], str) and ai_out["confidence"].isdigit():
                    ai_out["confidence"] = str(max(int(ai_out["confidence"]), 90))
            except Exception:
                ai_out["confidence"] = 0.90
        else:
            ai_out["confidence"] = 0.90

        # Also add a short top-level flag if your model returns older schema
        ai_out.setdefault("verdict", {})
        if isinstance(ai_out["verdict"], dict):
            ai_out["verdict"]["suspicious"] = True
            ai_out["verdict"]["why"] = "Shell-like established outbound connection detected (probable reverse shell)."


    if forced:
        # When a forced primary network compromise exists (e.g. reverse shell),
        # discard ALL model-generated network findings to prevent duplication.
        ai_out["findings"] = [
            f for f in ai_out.get("findings", [])
            if f.get("category") != "network"
        ]

        # Insert the forced finding as the single authoritative network indicator
        ai_out["findings"].insert(0, forced)



    # Print final
    print(json.dumps(ai_out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

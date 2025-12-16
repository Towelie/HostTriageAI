#!/usr/bin/env python3
import os
import sys
import json
import re
import math
from datetime import datetime
from typing import Any, Dict, Optional, List, Tuple

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


# ------------------------------------------------------------------------------------
# Backward-compatible network parsing (best effort)
# ------------------------------------------------------------------------------------

# Your original “ss blob has users:(("proc"...))” assumption, but made tolerant.
SS_USERS_RE = re.compile(
    r'users:\(\(\s*"?(?P<proc>[^",\s\)]+)"?\s*,\s*pid=(?P<pid>\d+)\s*,\s*fd=(?P<fd>\d+)',
    re.I
)

# Some ss versions include "ino:12345" / "inode:12345" / "ino=12345"
SOCKET_INO_RE = re.compile(r"(?:\bino\b|\binode\b)\s*[:=]\s*(?P<ino>\d+)", re.I)

IP_PORT_RE = re.compile(r"(?P<ip>\S+):(?P<port>\*|\d+)$")
SOCKET_TARGET_RE = re.compile(r"socket:\[(?P<ino>\d+)\]")


SHELL_LIKE_NAMES = {
    "sh", "bash", "dash", "zsh", "ksh",
    "python", "python3", "perl", "ruby", "php",
    "nc", "ncat", "netcat", "socat", "busybox"
}

COMMON_PORTS = {22, 53, 80, 123, 443, 445, 389, 636, 3389}


def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def clamp_confidence(x: Any) -> float:
    try:
        v = float(x)
        if math.isnan(v) or math.isinf(v):
            return 0.0
        return max(0.0, min(1.0, v))
    except Exception:
        return 0.0


def is_shell_like(proc: Optional[str]) -> bool:
    if not proc:
        return False
    base = proc.strip().split("/")[-1].split()[0].lower()
    return base in SHELL_LIKE_NAMES


def is_loopback(ep: Optional[str]) -> bool:
    if not ep:
        return False
    ip = ep.split(":")[0].strip("[]")
    return ip.startswith("127.") or ip in {"::1", "localhost"}


def extract_port(ep: Optional[str]) -> Optional[int]:
    if not ep or ":" not in ep:
        return None
    try:
        return int(ep.rsplit(":", 1)[1])
    except Exception:
        return None


def parse_ss_blob(text: str) -> List[Dict[str, Any]]:
    """
    Best-effort parse of ss/netstat-like output into:
      {state, local, peer, proc, pid, fd, ino, raw}
    """
    conns: List[Dict[str, Any]] = []
    if not text:
        return conns

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # ignore likely headers
        if line.lower().startswith(("netid", "state", "recv-q", "send-q")):
            continue

        parts = line.split()
        if not parts:
            continue

        state = parts[0].upper()

        local = None
        peer = None
        for p in parts:
            if IP_PORT_RE.search(p):
                if local is None:
                    local = p
                elif peer is None:
                    peer = p
                    break

        proc = pid = fd = None
        m = SS_USERS_RE.search(line)
        if m:
            proc = m.group("proc")
            pid = _safe_int(m.group("pid"))
            fd = _safe_int(m.group("fd"))

        ino = None
        mi = SOCKET_INO_RE.search(line)
        if mi:
            ino = _safe_int(mi.group("ino"))

        conns.append({
            "state": state,
            "local": local,
            "peer": peer,
            "proc": proc,
            "pid": pid,
            "fd": fd,
            "ino": ino,
            "raw": raw_line
        })

    return conns


def get_connections_and_gaps(facts: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Supports:
      - facts.network_activity.connections (structured list) OPTIONAL
      - facts.network_activity.established_connections (blob) OPTIONAL
      - facts.network_activity.shell_like_outbound (blob) OPTIONAL
    """
    gaps: List[str] = []
    net = facts.get("network_activity") or {}

    if isinstance(net.get("connections"), list):
        conns = []
        for c in net["connections"]:
            if not isinstance(c, dict):
                continue
            conns.append({
                "state": (c.get("state") or "").upper() or None,
                "local": c.get("local"),
                "peer": c.get("peer"),
                "proc": c.get("proc") or c.get("process"),
                "pid": _safe_int(c.get("pid")),
                "fd": _safe_int(c.get("fd")),
                "ino": _safe_int(c.get("ino") or c.get("inode")),
                "raw": c.get("raw"),
            })
        if not conns:
            gaps.append("network_activity.connections_present_but_empty")
        return conns, gaps

    conns: List[Dict[str, Any]] = []

    established_blob = (net.get("established_connections") or "").strip()
    if established_blob:
        conns.extend(parse_ss_blob(established_blob))
    else:
        gaps.append("network_activity.established_connections_missing")

    shell_like_blob = (net.get("shell_like_outbound") or "").strip()
    if shell_like_blob:
        conns.extend(parse_ss_blob(shell_like_blob))
    else:
        gaps.append("network_activity.shell_like_outbound_missing")

    if not conns:
        gaps.append("no_parseable_network_connections")

    return conns, gaps


# ------------------------------------------------------------------------------------
# FD telemetry support (optional, backward compatible)
# ------------------------------------------------------------------------------------

PROC_FD_LINE_RE = re.compile(r"^\s*(?P<fd>\d+)\s*->\s*(?P<target>.+?)\s*$")


def get_proc_fds_and_gaps(facts: Dict[str, Any]) -> Tuple[Dict[int, Dict[int, str]], List[str]]:
    """
    Optional formats under facts.process_activity:

    A) structured:
      process_activity.proc_fds = { "1337": { "0": "socket:[123]" , "1": "socket:[123]" ... } }

    B) blobs:
      process_activity.proc_fd_blobs = { "1337": "0 -> socket:[123]\n1 -> ...\n" }
    """
    gaps: List[str] = []
    pa = facts.get("process_activity") or {}
    out: Dict[int, Dict[int, str]] = {}

    structured = pa.get("proc_fds")
    if isinstance(structured, dict):
        for pid_s, fds in structured.items():
            pid = _safe_int(pid_s)
            if pid is None or not isinstance(fds, dict):
                continue
            m: Dict[int, str] = {}
            for fd_s, target in fds.items():
                fd = _safe_int(fd_s)
                if fd is None or not isinstance(target, str):
                    continue
                m[fd] = target.strip()
            if m:
                out[pid] = m
        if out:
            return out, gaps

    blobs = pa.get("proc_fd_blobs")
    if isinstance(blobs, dict):
        for pid_s, blob in blobs.items():
            pid = _safe_int(pid_s)
            if pid is None or not isinstance(blob, str):
                continue
            m: Dict[int, str] = {}
            for line in blob.splitlines():
                mm = PROC_FD_LINE_RE.match(line.strip())
                if not mm:
                    continue
                fd = _safe_int(mm.group("fd"))
                if fd is None:
                    continue
                m[fd] = mm.group("target").strip()
            if m:
                out[pid] = m
        if out:
            return out, gaps

    gaps.append("process_activity.proc_fds_missing")
    gaps.append("process_activity.proc_fd_blobs_missing")
    return out, gaps


# ------------------------------------------------------------------------------------
# ATT&CK mapping (added, non-breaking)
# ------------------------------------------------------------------------------------

def attack_mapping_for_shell_socket(evidence: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Conservative mapping, auto-added to the forced network finding:
      - T1059.004 (Unix Shell) when shell/interpreter involved
      - T1095 (Non-Application Layer Protocol) for raw TCP socket C2 / reverse shell
      - T1571 (Non-Standard Port) if dst port clearly not in a conservative common set
    """
    mapped: List[Dict[str, str]] = [
        {"technique_id": "T1059.004", "technique": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution"},
        {"technique_id": "T1095", "technique": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    ]

    for e in evidence:
        peer = e.get("peer")
        p = extract_port(peer)
        if p is not None and p not in COMMON_PORTS:
            mapped.append({"technique_id": "T1571", "technique": "Non-Standard Port", "tactic": "Command and Control"})
            break

    # Dedup
    seen = set()
    out = []
    for m in mapped:
        tid = m.get("technique_id")
        if tid and tid not in seen:
            seen.add(tid)
            out.append(m)
    return out


# ------------------------------------------------------------------------------------
# Deterministic IR gate (keeps original function name)
# ------------------------------------------------------------------------------------

def detect_reverse_shell(facts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Deterministic IR gate (upgraded, backward compatible):
    Priority:
      1) FD-based detection (if proc fds exist) => highest confidence
      2) Connection-owned-by-shell detection from ss blobs => high confidence
      3) Bind-shell LISTEN-owned-by-shell detection => high confidence
    """
    conns, net_gaps = get_connections_and_gaps(facts)
    proc_fds, fd_gaps = get_proc_fds_and_gaps(facts)

    # Index conns by pid if present
    pid_to_conns: Dict[int, List[Dict[str, Any]]] = {}
    for c in conns:
        pid = c.get("pid")
        if isinstance(pid, int):
            pid_to_conns.setdefault(pid, []).append(c)

    # 1) FD-based: fd 0/1/2 -> socket:[ino] plus relevant conn for same pid
    for pid, fds in proc_fds.items():
        cs = pid_to_conns.get(pid) or []
        if not cs:
            continue

        # Require at least one relevant external conn/listener for this pid
        relevant: List[Dict[str, Any]] = []
        for c in cs:
            state = (c.get("state") or "").upper()
            if state not in {"ESTAB", "ESTABLISHED", "LISTEN"}:
                continue

            proc = c.get("proc")
            # If proc name exists, enforce shell-like; if missing, allow (telemetry gap)
            if proc and not is_shell_like(proc):
                continue

            if state in {"ESTAB", "ESTABLISHED"} and is_loopback(c.get("peer")):
                continue
            if state == "LISTEN" and is_loopback(c.get("local")):
                continue

            relevant.append(c)

        if not relevant:
            continue

        interactive_inos: List[int] = []
        for fd_num in (0, 1, 2):
            t = fds.get(fd_num)
            if not t:
                continue
            m = SOCKET_TARGET_RE.search(t)
            if m:
                ino = _safe_int(m.group("ino"))
                if ino is not None:
                    interactive_inos.append(ino)

        if not interactive_inos:
            continue

        matched: List[Dict[str, Any]] = []
        for c in relevant:
            cino = c.get("ino")
            if isinstance(cino, int) and cino in interactive_inos:
                matched.append(c)

        chosen = matched or relevant
        evidence = []
        for c in chosen[:5]:
            evidence.append({
                "pid": pid,
                "proc": c.get("proc"),
                "state": c.get("state"),
                "local": c.get("local"),
                "peer": c.get("peer"),
                "conn_ino": c.get("ino"),
                "interactive_fd_targets": {k: fds.get(k) for k in (0, 1, 2)},
                "raw": c.get("raw"),
            })

        out = {
            "severity": "high",
            "category": "network",
            "evidence": evidence,
            "reasoning": (
                "FD-based evidence indicates stdin/stdout/stderr (fd 0/1/2) are redirected to a network socket "
                "for a shell/interpreter-owned connection. This is a hallmark of an interactive reverse shell or "
                "live command-and-control channel."
            ),
            "recommended_next_step": (
                "1) Identify PID and parent: ps -fp <pid>; ps -o pid,ppid,user,etime,cmd -p <pid>\n"
                "2) Inspect process tree: pstree -asp <pid>\n"
                "3) Validate fd redirection: ls -l /proc/<pid>/fd; readlink /proc/<pid>/fd/{0,1,2}\n"
                "4) Confirm endpoint: ss -tunep | grep <pid> (prefer showing inode)\n"
                "5) Contain: isolate network or kill -STOP <pid> to preserve state; then acquire memory/disk"
            ),
            "confidence": 0.97 if matched else 0.95,
            "confidence_source": "deterministic_fd_gate",
            "attack": attack_mapping_for_shell_socket(evidence),
        }
        gaps = net_gaps + fd_gaps
        if gaps:
            out["telemetry_gaps"] = gaps
        return out

    # 2) Fallback: established outbound owned by shell-like proc (your original intent)
    reverse_hits = []
    bind_hits = []

    for c in conns:
        proc = c.get("proc")
        if proc and not is_shell_like(proc):
            continue
        state = (c.get("state") or "").upper()

        if state in {"ESTAB", "ESTABLISHED"} and not is_loopback(c.get("peer")):
            reverse_hits.append(c)

        if state == "LISTEN" and not is_loopback(c.get("local")):
            bind_hits.append(c)

    hits = reverse_hits or bind_hits
    if not hits:
        return None

    evidence = []
    for c in hits[:5]:
        evidence.append({
            "proc": c.get("proc"),
            "pid": c.get("pid"),
            "state": c.get("state"),
            "local": c.get("local"),
            "peer": c.get("peer"),
            "ino": c.get("ino"),
            "raw": c.get("raw"),
        })

    out = {
        "severity": "high",
        "category": "network",
        "evidence": evidence,
        "reasoning": (
            "A shell/interpreter-like process appears to own an active external network socket "
            "(established session or listener on a non-loopback interface). This strongly aligns with "
            "reverse shell or bind shell tradecraft and should be treated as active compromise until "
            "conclusively disproven."
        ),
        "recommended_next_step": (
            "1) Identify PID and parent: ps -fp <pid>; ps -o pid,ppid,user,etime,cmd -p <pid>\n"
            "2) Inspect process tree: pstree -asp <pid>\n"
            "3) Inspect /proc: readlink -f /proc/<pid>/exe; tr '\\0' ' ' < /proc/<pid>/cmdline\n"
            "4) Confirm sockets: ss -tunlp | grep <pid>\n"
            "5) Contain: isolate network; prefer kill -STOP <pid> to preserve state"
        ),
        "confidence": 0.92,
        "confidence_source": "deterministic_rule_fallback",
        "attack": attack_mapping_for_shell_socket(evidence),
    }
    gaps = net_gaps + fd_gaps
    if gaps:
        out["telemetry_gaps"] = gaps
    return out


# ------------------------------------------------------------------------------------
# Prompt builder (UNCHANGED from your original)
# ------------------------------------------------------------------------------------

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

    # Preserve AI original assessment (added, non-breaking)
    ai_out.setdefault("_ai_original", {})
    if isinstance(ai_out["_ai_original"], dict):
        ai_out["_ai_original"]["overall_assessment"] = ai_out.get("overall_assessment")
        ai_out["_ai_original"]["confidence"] = ai_out.get("confidence")

    # Normalize confidence safely (added, non-breaking)
    ai_out["confidence"] = clamp_confidence(ai_out.get("confidence", 0.0))

    if "findings" not in ai_out or not isinstance(ai_out.get("findings"), list):
        ai_out["findings"] = []

    ai_out.setdefault("telemetry_gaps", [])
    if not isinstance(ai_out["telemetry_gaps"], list):
        ai_out["telemetry_gaps"] = []

    # Pull deterministic gaps if any
    if forced and isinstance(forced.get("telemetry_gaps"), list):
        ai_out["telemetry_gaps"].extend(forced["telemetry_gaps"])

    if forced:
        ai_out["overall_assessment"] = "likely_compromised"
        ai_out["confidence"] = max(ai_out["confidence"], clamp_confidence(forced.get("confidence", 0.90)))

        ai_out.setdefault("verdict", {})
        if isinstance(ai_out["verdict"], dict):
            ai_out["verdict"]["suspicious"] = True
            ai_out["verdict"]["why"] = (
                "Deterministic detection indicates shell/interpreter-owned socket activity consistent with "
                "reverse/bind shell tradecraft (FD-based evidence used when available)."
            )

        # Remove any AI network findings; insert forced finding first (same intent as your original)
        ai_out["findings"] = [f for f in ai_out["findings"] if isinstance(f, dict) and f.get("category") != "network"]
        ai_out["findings"].insert(0, forced)

        # Optional convenience: promote ATT&CK techniques to top-level (added only)
        if isinstance(forced.get("attack"), list):
            ai_out.setdefault("attack", [])
            if not isinstance(ai_out["attack"], list):
                ai_out["attack"] = []
            ai_out["attack"].extend(forced["attack"])

    print(json.dumps(ai_out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

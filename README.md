# Linux AI Host Anomaly Detection

A lightweight Linux host telemetry collector and AI-assisted analyzer designed for **incident response (IR) triage** and **post-compromise validation**.

This project combines **deterministic, code-enforced compromise detection** with **AI-assisted contextual analysis** to help analysts answer one core question quickly and accurately:

> “Is this host showing signs of active or likely compromise, and why?”

---

## Design Goals

- **Detection correctness over verbosity**  
  The tool prioritizes signals that reliably indicate compromise or attacker control.

- **Clear separation of authority**  
  Detection logic is enforced in code.  
  The AI provides interpretation and context, not verdict authority.

- **Incident response–first perspective**  
  Output is structured for analysts, not dashboards.

- **Minimal assumptions about the environment**  
  No `systemd` dependency. Works on servers, containers, WSL, and minimal Linux installs.

---

## What the Tool Actively Detects

The analyzer distinguishes between **authoritative compromise indicators** and **contextual risk indicators**.

### Authoritative Compromise Indicators (Code-Enforced)

These signals are evaluated deterministically and **cannot be downgraded or ignored by the AI**:

- **Established outbound network connections owned by interactive shells or interpreters**
  - Examples: `sh`, `bash`, `python`, `perl`, `ruby`, `php`, `nc`, `socat`
  - Indicates live command execution or control channel
- **Shell-owned outbound TCP sessions**
  - Strong indicator of reverse shells or active C2
- **Interpreter processes with live network control paths**
  - Suggests attacker-driven execution rather than passive tooling

If any of the above are present, the host is treated as **actively compromised until disproven**.

---

### Contextual Risk Indicators (AI-Assessed)

These signals are **not inherently malicious**, but are relevant for understanding persistence, staging, or attack surface:

- **Persistence mechanisms**
  - User and system cron jobs
  - `init.d` services
  - `rc.local` presence or modification
- **Filesystem artifacts**
  - Executable files in `/tmp` or `/dev/shm`
  - World-writable or user-owned executables in transient directories
- **Process characteristics**
  - Long-lived user processes
  - Root-owned services with unusual arguments
- **Privilege and access**
  - UID 0 users
  - Sudoers configuration and overrides
- **Installed software profile**
  - Presence of service-oriented packages (SSH, Docker, databases, web servers)
- **System role indicators**
  - Developer tooling
  - Data science or ML environments
  - Server-like vs workstation-like behavior

These are evaluated with calibrated severity and used to provide investigative context.

---

## Severity Model

Severity is intentionally conservative and proportional:

- **HIGH**
  - Live control paths (shell/interpreter network connections)
  - Active compromise indicators
- **MEDIUM**
  - Persistence mechanisms
  - Suspicious staging locations
  - Potential footholds not directly tied to live control
- **LOW**
  - Hygiene issues
  - Informational observations
  - Environment characterization

The analyzer avoids severity inflation and duplicate findings.

---

## Architecture Overview

```
collect.sh
  - Gathers high-signal host telemetry
  - Outputs a single compact JSON document

analyze.py
  - Enforces deterministic compromise detection
  - Calls an LLM for contextual analysis
  - Deduplicates findings and calibrates severity
  - Produces IR-grade JSON output
```

---

## Collected Telemetry

The collector intentionally limits scope to high-value artifacts:

- OS, kernel, uptime
- Running processes (root + long-lived)
- Network listeners
- Established outbound network connections
- Shell-owned outbound connections (explicitly flagged)
- System and user cron jobs
- `init.d` services and `rc.local`
- UID 0 users and sudoers hashes
- Executable artifacts in `/tmp` and `/dev/shm`
- Package inventory summary (service-oriented focus)

No full filesystem scans. No verbose logs.

---

## Output Format

The analyzer emits **strict JSON** suitable for IR workflows.

### Sanitized Example Finding

```json
{
  "severity": "high",
  "category": "network",
  "evidence": "tcp ESTAB local_host:54321 → remote_host:9003 users:((\"sh\",pid=XXXX))",
  "reasoning": "Established outbound connection owned by an interactive shell indicates a live control channel consistent with reverse shell or command-and-control tradecraft.",
  "recommended_next_step": "Identify the shell process and its parent, inspect process lineage, confirm the remote endpoint, and isolate the host."
}
```

### Example Overall Structure

```json
{
  "overall_assessment": "likely_compromised",
  "confidence": 0.95,
  "context_summary": [
    "Host appears to be a developer workstation",
    "No exposed server-style listeners detected",
    "Python tooling and mounted filesystem usage observed"
  ],
  "high_risk_indicators": [
    "Shell-owned outbound network connection"
  ],
  "findings": []
}
```

---

## Usage

Collect telemetry:

```bash
./collect.sh /var/tmp/ai_host_facts.json
```

Analyze:

```bash
python3 analyze.py /var/tmp/ai_host_facts.json
```

---

## Configuration

Create a `.env` file:

```
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx
```

Optional:

```
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

---

## Intended Use Cases

- Incident response triage
- Validation of suspected host compromise
- Developer workstation investigations
- WSL and container environment analysis
- Post-breach host assessment

---

## Disclaimer

This tool is provided for defensive security and incident response purposes only.  
All findings should be validated through additional investigation.

---

## License

GNU General Public License v3.0 (GPL-3.0)

---

## Project Status

Active development with emphasis on detection correctness, analyst usability, and disciplined severity handling.

Security-focused feedback and contributions are welcome.

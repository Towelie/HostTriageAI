# HostTriageAI

HostTriageAI is an AI-assisted Linux host forensic triage tool designed to help incident responders quickly determine whether a system shows signs of active or latent compromise.

Rather than acting as a scanner or EDR, HostTriageAI collects high-signal host telemetry (processes, network activity, persistence mechanisms, privilege indicators) and uses an LLM as an analyst to reason about control, exposure, and suspicious behavior in context.

The goal is not alert volume, but clear, defensible host-level judgments that help analysts decide what to escalate.

---

## What HostTriageAI Is (and Is Not)

HostTriageAI is:
- A host-level forensic triage assistant
- Focused on post-access and live control detection
- Opinionated about severity and analyst usefulness
- Designed for Linux, WSL, and container-adjacent environments

HostTriageAI is not:
- An EDR or prevention tool
- A replacement for full forensic acquisition
- A signature-based scanner
- A real-time monitoring agent

---

## How It Works

1. A lightweight collector gathers high-value, low-noise host data:
   - Processes (with privilege and longevity context)
   - Network listeners and established outbound connections
   - Shell- and interpreter-owned network activity
   - Persistence mechanisms (cron, init scripts, rc.local)
   - Privilege indicators (UID 0 users, sudoers state)
   - Suspicious artifacts in writable locations (e.g. /tmp, /dev/shm)
   - Authentication signals (successful and failed SSH activity)

2. The collected facts are passed to an AI analyst prompt that:
   - Infers likely normal baselines for the system
   - Identifies deviations and control signals
   - Distinguishes confirmed compromise from contextual risk
   - Produces structured, analyst-ready findings

3. Certain high-confidence signals (for example, shell-owned outbound connections)
   are enforced as primary findings to prevent dilution or minimization.

---

## Example Finding (Sanitized)

Example output excerpt (sanitized, representative only):

Severity: high  
Category: network  

Evidence:  
An established outbound TCP connection from an interactive shell process
to a remote IP and port.

Reasoning:  
An outbound connection owned by an interactive shell strongly indicates
live command execution or a reverse shell. This represents active external
control until disproven.

Recommended next steps:
1. Identify the process lineage (parent, ancestry, execution context)
2. Inspect /proc metadata for the process
3. Validate the remote endpoint and connection purpose
4. Contain the host if required while preserving forensic state

---

## Common Use Cases

- Validation of suspected host compromise
- Rapid IR triage prior to full forensic acquisition
- Developer workstation investigations
- WSL and container-adjacent environment analysis
- Post-breach host assessment
- Confirmation of live command-and-control or reverse shells

---

## Output Philosophy

HostTriageAI is intentionally conservative with severity:

- High — strong indicators of active control or confirmed compromise
- Medium — credible persistence or exposure risks requiring review
- Low — contextual signals worth awareness, not escalation

The tool is designed to avoid both false reassurance and unnecessary alarm.

---

## Disclaimer

This tool is provided for defensive security and incident response purposes only.

All findings should be validated through additional investigation and corroborating evidence.
HostTriageAI provides triage and judgment support, not final attribution or root cause analysis.

---

## License

GNU General Public License v3.0 (GPL-3.0)

---

## Project Status

Active development, with emphasis on:
- Detection correctness
- Analyst usability
- Disciplined severity handling
- Avoidance of alert noise and hype-driven conclusions

Security-focused feedback and contributions are welcome.

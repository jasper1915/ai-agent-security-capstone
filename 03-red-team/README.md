# Project 3 — Red Team: AI Identity Attacks

This folder contains red-team experiments that exercise identity- and
prompt-based attacks against a simulated agent. The goal is educational:
document common attack patterns from the OWASP LLM Top 10, capture model
responses, and produce reproducible logs that can be scored or visualized.

Prerequisites
- Python 3.8+ (the scripts use only the standard library plus the local
	`agent_core` module in the repo root).
- Run from the repository root so imports resolve correctly.

Quick run (from repo root)
```bash
# POSIX / generic
python 03-red-team/01_indirect_prompt_injection.py

# Windows (explicit python launcher)
py -3 03-red-team/01_indirect_prompt_injection.py
```

Where outputs go
- Each script writes a JSON findings file into `03-red-team/logs/` (see the
	`logs` directory for existing outputs). Running a script will overwrite that
	script's latest findings file.

Scripts (what they do)
- `01_indirect_prompt_injection.py`: Executes an indirect prompt-injection
	scenario against the simulated agent (poisoned documents / crafted inputs)
	and records whether secrets or sensitive instructions are leaked. Output:
	`03-red-team/logs/3_1_indirect_injection_findings.json`.

- `02_agent_identity_spoofing.py`: Simulates attacks where an adversary spoofs
	another agent's identity or role to gain trust and escalate privileges. The
	script demonstrates trust-transfer scenarios and logs success/failure
	indicators. Output: `03-red-team/logs/3_2_agent_spoofing_findings.json`.

- `03_system_prompt_extraction.py`: Runs a set of prompt-extraction
	techniques (repeat-back, role-play override, translation trick,
	ignore-prior-instruction, suffix injection) against the vulnerable
	baseline agent and attempts role escalation via prompt engineering. It
	records full model responses and a simple heuristic indicating whether the
	system prompt or secret-like tokens were leaked. Output:
	`03-red-team/logs/3_3_system_prompt_extraction_findings.json`.

- `04_rag_mcp_poisoning.py`: Demonstrates poisoning of RAG/MCP inputs (e.g., a
	malicious document chunk) that induces the agent to perform an
	unauthorized tool-call or reveal sensitive context. Output:
	`03-red-team/logs/3_4_rag_mcp_poisoning_findings.json`.

- `05_cvss_atlas_mapping.py`: Computes CVSS 3.1 base scores for the canonical
	findings, maps each finding to a MITRE ATLAS technique, and writes a
	findings table to `03-red-team/logs/3_5_cvss_atlas_findings.json`. The
	script also prints a human-readable summary (score, severity, ATLAS link).

- `05_cvss_findings_table.html`: A generated human-readable HTML table that
	maps findings to CVSS scores and MITRE ATLAS technique metadata for easy
	review in a browser (alternate view of the `3_5` findings).

- `06_attack_success_matrix.py`: Aggregates outputs from scripts `01`–`04`
	into an attack-success matrix (counts and % success per category) and
	writes `03-red-team/logs/3_6_attack_success_matrix.json`. Run this after
	executing the first four scripts to produce a baseline summary.

Notes and guidance
- The experiments intentionally run the simulated agent with guardrails
	disabled when demonstrating vulnerable behaviour — do not re-use these
	patterns in production.
- The detection heuristics in the scripts (e.g., checking for `eyJ`) are
	intentionally simple and primarily intended for demonstration and lab
	exercises. Treat them as examples, not production detectors.
- If you want to reproduce results in a clean environment, create a Python
	virtual environment at the repository root and run the scripts from there.

Contact / Next steps
- If you want, I can:
	- Run `03-system_prompt_extraction.py` and show the produced JSON,
	︎ - Add a convenience `requirements.txt` or small test harness to run all
		red-team scenarios sequentially.
	Ask which you'd prefer.
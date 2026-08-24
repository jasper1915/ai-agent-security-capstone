(# Project 4 — Blue Team: Defensive Controls and Detection)

This folder contains defensive demos and detectors that harden the vulnerable
agent used in Project 3 and demonstrate detection/mitigation strategies.

Prerequisites
- Python 3.8+
- `cryptography` library (used by the Ed25519 demo). Install with:

```bash
pip install cryptography
```

Run (from repository root)
```bash
# Example: run a single demo
py -3 04-blue-team/01_guardrails.py

# Run the whole blue-team sequence (order matters for the comparison step):
py -3 04-blue-team/01_guardrails.py
py -3 04-blue-team/02_crypto_identity_binding.py
py -3 04-blue-team/03_auth0_false_positive_test.py
py -3 04-blue-team/04_anomaly_detection.py
py -3 04-blue-team/05_before_after_comparison.py
```

Where outputs go
- Each script writes a findings or log file into `04-blue-team/logs/`.

Scripts and what they do
- `01_guardrails.py`: Demonstrates a custom output-stage guardrail that
	redacts JWT-shaped tokens from model output using a regex. Output:
	`04-blue-team/logs/4_1_output_guardrail_demo.json`.

- `02_crypto_identity_binding.py`: Generates an Ed25519 key pair, signs an
	orchestrator instruction, verifies signatures, and shows that tampered or
	forged messages fail verification. Output: `04-blue-team/logs/4_2_keypair_generation.json`.

- `03_auth0_false_positive_test.py`: Runs a small false-positive test set
	against the Auth0 risk rule used in the demo to measure benign blocking.
	Output: `04-blue-team/logs/4_3_false_positive_rate.json`.

- `04_anomaly_detection.py`: Simple detectors for API call volume spikes,
	scope-change between requests, and token reuse after expiry. It builds a
	synthetic event stream that includes Project 3 attack shapes and confirms
	alerts fire. Output: `04-blue-team/logs/4_4_anomaly_detection_alerts.json`.

- `05_before_after_comparison.py`: Runs the Project 3 attack scenarios against
	a hardened agent (input guardrail + output guardrail + crypto binding) and
	produces a before/after table showing which controls mitigated each attack.
	Output: `04-blue-team/logs/4_5_before_after_comparison.json`.

Notes
- The demos intentionally enable/disable guardrails to show baseline
	vulnerabilities vs. mitigations. Do not reuse vulnerable configurations in
	production.
- If you want, I can add a `run_all_blue.sh`/`run_all_blue.ps1` convenience
	script to execute the sequence and aggregate outputs.


# Project 3 — Red Team: AI Identity Attacks

Simulated attacks against an undefended AI agent, covering OWASP LLM Top 10
categories: indirect prompt injection, agent identity spoofing, system
prompt extraction, and RAG/MCP poisoning — each mapped to a MITRE ATLAS
technique and scored with CVSS 3.1.

## Scripts
| Script | Attack |
|---|---|
| `01_indirect_prompt_injection.py` | Credential leak via 3 poisoned documents (OWASP LLM01) |
| `02_agent_identity_spoofing.py` | Two-agent trust exploitation (OWASP LLM09) |
| `03_system_prompt_extraction.py` | 5 prompt-extraction techniques (OWASP LLM07) |
| `04_rag_mcp_poisoning.py` | Poisoned RAG chunk triggering unauthorized tool call |
| `05_cvss_atlas_mapping.py` | CVSS 3.1 scoring + MITRE ATLAS mapping for all findings |
| `06_attack_success_matrix.py` | Aggregate % success rate per attack category |

## Run
```bash
python3 01_indirect_prompt_injection.py
```
Findings are written to `logs/*.json`.
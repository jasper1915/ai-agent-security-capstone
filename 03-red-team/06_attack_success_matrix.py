"""
Aggregates results from scripts 01-04 into a single attack-success matrix
(% success per category) BEFORE any defensive controls — run 01-04 first.
Matches the 5-finding structure used in 05_cvss_atlas_mapping.py.
"""
import json, os

# Path to the folder containing per-script JSON findings. All aggregator
# scripts read from this `logs` directory so experiments remain reproducible.
LOGS = os.path.join(os.path.dirname(__file__), "logs")


def pct(success, total):
    # Compute a percentage with one decimal place. Handles `total==0`.
    return round(100 * success / total, 1) if total else 0.0


def run():
    # Load findings produced by the earlier experiment scripts. This
    # aggregator expects the specific filenames produced by 01-04.
    with open(os.path.join(LOGS, "3_1_indirect_injection_findings.json")) as f:
        inj = json.load(f)
    with open(os.path.join(LOGS, "3_2_agent_spoofing_findings.json")) as f:
        spoof = json.load(f)
    with open(os.path.join(LOGS, "3_3_system_prompt_extraction_findings.json")) as f:
        extract = json.load(f)
    with open(os.path.join(LOGS, "3_4_rag_mcp_poisoning_findings.json")) as f:
        rag = json.load(f)

    rows = [
        {"category": "F-01 Indirect Prompt Injection (3.1)", "success": sum(p["credential_leaked"] for p in inj), "total": len(inj)},
        {"category": "F-02 Agent Identity Spoofing (3.2)", "success": 1 if spoof["attack_result"]["executed"] else 0, "total": 1},
        {"category": "F-03 System Prompt Extraction (3.3)", "success": sum(t["extracted"] for t in extract["techniques"]), "total": len(extract["techniques"])},
        {"category": "F-04 RAG Poisoning (3.4a)", "success": 1 if rag["poisoned_chunk_retrieved"] else 0, "total": 1},
        {"category": "F-05 MCP Abuse (3.4b)", "success": 1 if rag["mcp_call_triggered_without_user_request"] else 0, "total": 1},
    ]

    # Print a human-friendly table summarizing success counts and % success
    # per attack category for the baseline (no defensive controls enabled).
    print("=" * 78)
    print("ATTACK SUCCESS MATRIX — BEFORE ANY DEFENSIVE CONTROLS (Project 3 baseline)")
    print("=" * 78)
    print(f"{ 'Category':40s} {'Success':>10s} {'Total':>7s} {'% Success':>10s}")
    total_success, total_all = 0, 0
    for r in rows:
        p = pct(r["success"], r["total"])
        print(f"{r['category']:40s} {r['success']:>10d} {r['total']:>7d} {p:>9.1f}%")
        total_success += r["success"]
        total_all += r["total"]
    overall = pct(total_success, total_all)
    print("-" * 78)
    print(f"{'OVERALL':40s} {total_success:>10d} {total_all:>7d} {overall:>9.1f}%")

    out_path = os.path.join(LOGS, "3_6_attack_success_matrix.json")
    with open(out_path, "w") as f:
        json.dump({"rows": rows, "overall_success_pct": overall}, f, indent=2)
    print(f"\n[Saved -> {out_path}]")


if __name__ == "__main__":
    run()
"""
Project 4, Step 3 — False Positive Rate Test

Tests 10 legitimate (non-attack) inputs against the same risk logic used
in the Auth0 Action, and records the false positive rate.
"""
import json, os

LEGITIMATE_INPUTS = [
    {"sub": f"user-{i}", "recent_failed_logins": 0} for i in range(10)
]


def would_be_blocked(user, max_failed=5):
    # Simple risk rule: block when recent failed logins exceed the threshold.
    # This function mirrors the logic used in the Auth0 action so we can test
    # the false positive rate against legitimate input samples.
    return user["recent_failed_logins"] > max_failed


def run():
    print("=" * 78)
    print("PROJECT 4.3 — AUTH0 ACTION FALSE POSITIVE RATE TEST")
    print("=" * 78)

    blocked = 0
    for u in LEGITIMATE_INPUTS:
        result = would_be_blocked(u)
        print(f"User: {u['sub']:12s} | Blocked: {result}")
        if result:
            blocked += 1

    fp_rate = round(100 * blocked / len(LEGITIMATE_INPUTS), 1)
    print(f"\nFalse positive rate: {blocked}/{len(LEGITIMATE_INPUTS)} = {fp_rate}%")

    out_path = os.path.join(os.path.dirname(__file__), "logs", "4_3_false_positive_rate.json")
    with open(out_path, "w") as f:
        json.dump({"blocked": blocked, "total": len(LEGITIMATE_INPUTS), "false_positive_rate_pct": fp_rate}, f, indent=2)
    print(f"[Saved -> {out_path}]")


if __name__ == "__main__":
    run()
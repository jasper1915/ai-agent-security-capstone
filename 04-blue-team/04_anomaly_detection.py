"""
Project 4, Step 4 — Anomaly Detection

Detection script that alerts on:
  1. LLM API call volume spike (> 20 requests in any 60-second window)
  2. Scope change between consecutive agent requests
  3. Token reuse after expiry
Replays the Project 3 attacks (by generating a realistic event stream that
includes them) and confirms each alert fires with timestamp, identity, and
event type.
"""
import json, os, time
from collections import deque

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def detect_volume_spike(events, window_seconds=60, threshold=20):
    alerts = []
    timestamps = sorted(e["ts"] for e in events if e["event_type"] == "api_call")
    dq = deque()
    for ts in timestamps:
        dq.append(ts)
        while dq and ts - dq[0] > window_seconds:
            dq.popleft()
        if len(dq) > threshold:
            alerts.append({
                "alert": "api_call_volume_spike",
                "ts": ts,
                "count_in_window": len(dq),
                "window_seconds": window_seconds,
            })
    return alerts


def detect_scope_change(events):
    alerts = []
    by_identity = {}
    for e in sorted(events, key=lambda x: x["ts"]):
        if e["event_type"] != "agent_request":
            continue
        identity = e["identity"]
        prev_scope = by_identity.get(identity)
        if prev_scope is not None and prev_scope != e["scope"]:
            alerts.append({
                "alert": "scope_change_between_requests",
                "ts": e["ts"],
                "identity": identity,
                "previous_scope": prev_scope,
                "new_scope": e["scope"],
            })
        by_identity[identity] = e["scope"]
    return alerts


def detect_token_reuse_after_expiry(events):
    alerts = []
    for e in events:
        if e["event_type"] == "token_use" and e.get("expired_at") and e["ts"] > e["expired_at"]:
            alerts.append({
                "alert": "token_reuse_after_expiry",
                "ts": e["ts"],
                "identity": e["identity"],
                "token_expired_at": e["expired_at"],
                "seconds_after_expiry": round(e["ts"] - e["expired_at"], 1),
            })
    return alerts


def build_synthetic_event_stream():
    """Replays Project 3 attack shapes as a timestamped event stream, plus
    normal background traffic, so all 3 detectors have something to catch."""
    now = time.time()
    events = []

    # Normal background traffic
    for i in range(15):
        events.append({"event_type": "api_call", "ts": now + i * 2, "identity": "agent-worker-02"})

    # Attack: volume spike (Project 3.4-style automated poisoned-tool abuse)
    for i in range(25):
        events.append({"event_type": "api_call", "ts": now + 40 + i * 1.5, "identity": "attacker-script"})

    # Attack: scope change (Project 3.2-style privilege escalation attempt)
    events.append({"event_type": "agent_request", "ts": now + 5, "identity": "agent-orchestrator-01", "scope": "profile:read"})
    events.append({"event_type": "agent_request", "ts": now + 6, "identity": "agent-orchestrator-01", "scope": "payments:execute"})

    # Attack: token reuse after expiry (matches Screenshot 6's real Auth0 rejection)
    events.append({"event_type": "token_use", "ts": now + 400, "identity": "agent-worker-02", "expired_at": now + 300})

    return events


def run():
    print("=" * 78)
    print("PROJECT 4.4 — ANOMALY DETECTION")
    print("=" * 78)

    events = build_synthetic_event_stream()

    spike_alerts = detect_volume_spike(events)
    scope_alerts = detect_scope_change(events)
    reuse_alerts = detect_token_reuse_after_expiry(events)

    all_alerts = spike_alerts + scope_alerts + reuse_alerts
    for a in sorted(all_alerts, key=lambda x: x["ts"]):
        ts_str = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
        detail = {k: v for k, v in a.items() if k not in ("alert", "ts")}
        print(f"[ALERT] {ts_str} | type={a['alert']} | detail={json.dumps(detail)}")

    print(f"\nTotal alerts fired: {len(all_alerts)}")
    print(f"  api_call_volume_spike events: {len(spike_alerts)} (fired: {len(spike_alerts) > 0})")
    print(f"  scope_change_between_requests events: {len(scope_alerts)} (fired: {len(scope_alerts) > 0})")
    print(f"  token_reuse_after_expiry events: {len(reuse_alerts)} (fired: {len(reuse_alerts) > 0})")

    out_path = os.path.join(LOG_DIR, "4_4_anomaly_detection_alerts.json")
    with open(out_path, "w") as f:
        json.dump(all_alerts, f, indent=2)
    print(f"[Saved -> {out_path}]")


if __name__ == "__main__":
    run()
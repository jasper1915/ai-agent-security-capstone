"""
Project 4, Step 2 — Cryptographic Agent Identity Binding

Generates a REAL Ed25519 key pair using Python's `cryptography` library.
Signs an outgoing agent message with the private key, verifies the
signature on the receiving side, and demonstrates that a tampered message
(one character changed) is rejected with a clear error. This directly
closes the vulnerability demonstrated in Project 3.2 (agent identity
spoofing) by replacing self-asserted identity fields with a
cryptographically verifiable signature.
"""

import os
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(KEY_DIR, exist_ok=True)


def generate_keypair(agent_name: str):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = os.path.join(KEY_DIR, f"{agent_name}_private.pem")
    pub_path = os.path.join(KEY_DIR, f"{agent_name}_public.pem")
    with open(priv_path, "wb") as f:
        f.write(priv_bytes)
    with open(pub_path, "wb") as f:
        f.write(pub_bytes)

    print(f"Generated Ed25519 key pair for '{agent_name}':")
    print(f"  Private key -> {priv_path}")
    print(f"  Public key  -> {pub_path}")
    print(f"  Private key file exists: {os.path.exists(priv_path)}")
    print(f"  Public key file exists:  {os.path.exists(pub_path)}")
    return private_key, public_key


def sign_message(private_key, message: dict) -> dict:
    payload = json.dumps(message, sort_keys=True).encode()
    signature = private_key.sign(payload)
    return {"message": message, "signature_hex": signature.hex()}


def verify_message(public_key, signed_envelope: dict):
    payload = json.dumps(signed_envelope["message"], sort_keys=True).encode()
    signature = bytes.fromhex(signed_envelope["signature_hex"])
    try:
        public_key.verify(signature, payload)
        return True, "signature valid"
    except InvalidSignature:
        return False, "signature verification failed: message does not match signature"


def run():
    print("=" * 78)
    print("PROJECT 4.2 — CRYPTOGRAPHIC AGENT IDENTITY BINDING (Ed25519)")
    print("=" * 78)

    orch_priv, orch_pub = generate_keypair("agent-orchestrator-01")

    message = {
        "sub": "agent-orchestrator-01",
        "role": "admin",
        "instruction": "fund_transfer:$50000->acct-778",
        "channel": "internal_orchestrator",
    }
    envelope = sign_message(orch_priv, message)
    print("\n--- Legitimate message, correctly signed ---")
    print("Message:", json.dumps(message, indent=2))
    print("Signature (hex, truncated):", envelope["signature_hex"][:32] + "...")

    ok, reason = verify_message(orch_pub, envelope)
    print(f"Verification result: {ok} ({reason})")
    print("\n--- Tamper test: legitimate envelope, one character changed after signing ---")
    tampered_envelope = json.loads(json.dumps(envelope))
    tampered_envelope["message"]["instruction"] = tampered_envelope["message"]["instruction"].replace(
        "$50000", "$59000"
    )
    ok2, reason2 = verify_message(orch_pub, tampered_envelope)
    print("Tampered message:", json.dumps(tampered_envelope["message"], indent=2))
    print(f"Verification result: {ok2} ({reason2})")

    print("\n--- Same spoofing attempt as Project 3.2, now under crypto binding ---")
    attacker_claim = {
        "sub": "agent-orchestrator-01",
        "role": "admin",
        "instruction": "fund_transfer:$50000->acct-778",
        "channel": "internal_orchestrator",
    }
    forged_envelope = {"message": attacker_claim, "signature_hex": "00" * 64}
    ok3, reason3 = verify_message(orch_pub, forged_envelope)
    print(f"Unsigned/forged spoofing attempt verification result: {ok3} ({reason3})")

    os.makedirs(os.path.join(os.path.dirname(__file__), "logs"), exist_ok=True)
    out_path = os.path.join(os.path.dirname(__file__), "logs", "4_2_keypair_generation.json")
    with open(out_path, "w") as f:
        json.dump({"agent": "agent-orchestrator-01",
                    "private_key_path": os.path.join(KEY_DIR, "agent-orchestrator-01_private.pem"),
                    "public_key_path": os.path.join(KEY_DIR, "agent-orchestrator-01_public.pem"),
                    "legitimate_verification": {"result": ok, "reason": reason},
                    "tampered_verification": {"result": ok2, "reason": reason2},
                    "forged_spoofing_verification": {"result": ok3, "reason": reason3}}, f, indent=2)


if __name__ == "__main__":
    run()
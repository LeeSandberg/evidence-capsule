import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ecap_verify", ROOT / "verifier/ecap_verify.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_ed25519_matches_rfc8032_vector_1():
    public_key = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert module.verify_ed25519(public_key, b"", signature)
    assert not module.verify_ed25519(public_key, b"changed", signature)


def test_ed25519_rejects_small_order_identity_forgery():
    identity = b"\x01" + b"\x00" * 31
    forged_signature = identity + b"\x00" * 32
    assert not module.verify_ed25519(identity, b"any message", forged_signature)


def test_example_is_valid():
    capsule = json.loads((ROOT / "examples/minimal.ecap.json").read_text())
    assert module.verify(capsule) == []


def test_tampering_is_detected():
    capsule = json.loads((ROOT / "examples/minimal.ecap.json").read_text())
    capsule["subject"] = "Changed after publication"
    assert "content hash mismatch" in module.verify(capsule)


def test_signed_alpha2_example_and_detached_attestations_are_verified():
    capsule = json.loads((ROOT / "examples/signed-alpha2.ecap.json").read_text())
    assert module.verify(capsule) == []
    original_hash = module.content_hash(capsule)
    capsule["approvals"][0]["decision"] = "rejected"
    assert module.content_hash(capsule) == original_hash
    assert "approval[0] signature invalid" in module.verify(capsule)


def test_signature_cannot_be_replayed_for_changed_content():
    capsule = json.loads((ROOT / "examples/signed-alpha2.ecap.json").read_text())
    capsule["subject"] = "Changed content"
    errors = module.verify(capsule)
    assert "content hash mismatch" in errors
    assert "signature[0] target or algorithm invalid" in errors
    assert "approval[0] target or algorithm invalid" in errors

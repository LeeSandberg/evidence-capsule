import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ecap_verify", ROOT / "verifier/ecap_verify.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_example_is_valid():
    capsule = json.loads((ROOT / "examples/minimal.ecap.json").read_text())
    assert module.verify(capsule) == []


def test_tampering_is_detected():
    capsule = json.loads((ROOT / "examples/minimal.ecap.json").read_text())
    capsule["subject"] = "Changed after publication"
    assert "content hash mismatch" in module.verify(capsule)

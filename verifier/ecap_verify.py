#!/usr/bin/env python3
"""Dependency-free Evidence Capsule 1.0 alpha integrity verifier."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

FORMAT = "evidence-capsule/1.0.0-alpha.1"
REQUIRED = {"format", "capsule_id", "revision", "subject", "claims", "evidence", "policy_results", "integrity"}
ALLOWED = REQUIRED | {
    "previous_revision_hash", "assumptions", "contradictions", "model_outputs",
    "provenance", "signatures", "external_anchors",
}


def canonical_payload(capsule: dict) -> bytes:
    unsigned = {key: value for key, value in capsule.items() if key != "integrity"}
    return json.dumps(unsigned, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def content_hash(capsule: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_payload(capsule)).hexdigest()


def verify(capsule: dict) -> list[str]:
    errors = []
    missing = REQUIRED - capsule.keys()
    unknown = capsule.keys() - ALLOWED
    if missing:
        errors.append("missing fields: " + ", ".join(sorted(missing)))
    if unknown:
        errors.append("unknown fields: " + ", ".join(sorted(unknown)))
    if capsule.get("format") != FORMAT:
        errors.append("unsupported format")
    if not isinstance(capsule.get("revision"), int) or capsule.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    for field in ("claims", "evidence", "policy_results"):
        if not isinstance(capsule.get(field), list):
            errors.append(f"{field} must be an array")
    integrity = capsule.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        errors.append("integrity.algorithm must be sha256")
    elif integrity.get("content_hash") != content_hash(capsule):
        errors.append("content hash mismatch")
    return errors


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: ecap_verify.py CAPSULE", file=sys.stderr)
        return 2
    try:
        capsule = json.loads(Path(sys.argv[1]).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"invalid capsule: {exc}", file=sys.stderr)
        return 2
    errors = verify(capsule)
    if errors:
        print("INVALID: " + "; ".join(errors), file=sys.stderr)
        return 1
    print(f"VALID {capsule['integrity']['content_hash']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

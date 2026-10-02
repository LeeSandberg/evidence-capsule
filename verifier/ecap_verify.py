#!/usr/bin/env python3
"""Dependency-free Evidence Capsule integrity and Ed25519 verifier."""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ALPHA1 = "evidence-capsule/1.0.0-alpha.1"
ALPHA2 = "evidence-capsule/1.0.0-alpha.2"
REQUIRED = {"format", "capsule_id", "revision", "subject", "claims", "evidence", "policy_results", "integrity"}
ALLOWED = REQUIRED | {"previous_revision_hash", "assumptions", "contradictions", "model_outputs",
                      "provenance", "signatures", "approvals", "external_anchors"}
Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
I = pow(2, (Q - 1) // 4, Q)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def canonical_payload(capsule: dict) -> bytes:
    excluded = {"integrity"}
    if capsule.get("format") == ALPHA2:
        excluded |= {"signatures", "approvals"}
    return _canonical({key: value for key, value in capsule.items() if key not in excluded})


def content_hash(capsule: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_payload(capsule)).hexdigest()


def signature_message(signature: dict) -> bytes:
    statement = {key: value for key, value in signature.items() if key != "signature"}
    return b"evidence-capsule-signature/v1\0" + _canonical(statement)


def approval_message(approval: dict) -> bytes:
    statement = {key: value for key, value in approval.items() if key != "signature"}
    return b"evidence-capsule-approval/v1\0" + _canonical(statement)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, Q - 2, Q) % Q
    x = pow(xx, (Q + 3) // 8, Q)
    if (x * x - xx) % Q:
        x = x * I % Q
    if x & 1:
        x = Q - x
    return x


def _decode_point(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    y, sign = value & ((1 << 255) - 1), value >> 255
    if y >= Q:
        raise ValueError("non-canonical Ed25519 point")
    x = _xrecover(y)
    if (y * y - x * x - 1 - D * x * x * y * y) % Q:
        raise ValueError("invalid Ed25519 point")
    if (x & 1) != sign:
        x = Q - x
    return x, y


def _add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    product = D * x1 * x2 * y1 * y2 % Q
    return ((x1 * y2 + x2 * y1) * pow(1 + product, Q - 2, Q) % Q,
            (y1 * y2 + x1 * x2) * pow(1 - product, Q - 2, Q) % Q)


def _multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


BASE = (_xrecover(4 * pow(5, Q - 2, Q) % Q), 4 * pow(5, Q - 2, Q) % Q)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        r_encoded, scalar = signature[:32], int.from_bytes(signature[32:], "little")
        if scalar >= L:
            return False
        public, r_point = _decode_point(public_key), _decode_point(r_encoded)
        challenge = int.from_bytes(
            hashlib.sha512(r_encoded + public_key + message).digest(), "little"
        ) % L
        return _multiply(_multiply(BASE, scalar), 8) == _multiply(
            _add(r_point, _multiply(public, challenge)), 8
        )
    except (ValueError, ZeroDivisionError):
        return False


def _verify_attestation(item: object, message_builder, digest: str, label: str) -> list[str]:
    if not isinstance(item, dict):
        return [f"{label} must be an object"]
    required = {"profile", "algorithm", "key_id", "public_key", "signed_at",
                "content_hash", "signature"}
    if not required <= item.keys():
        return [f"{label} missing fields"]
    if item["algorithm"] != "Ed25519" or item["content_hash"] != digest:
        return [f"{label} target or algorithm invalid"]
    if label.startswith("signature"):
        if item.get("profile") != "evidence-capsule-signature/1" or not item.get("signer") or not item.get("role"):
            return [f"{label} profile invalid"]
    elif (item.get("profile") != "evidence-capsule-approval/1"
          or item.get("decision") not in {"approved", "rejected", "needs_changes"}
          or not item.get("reviewer") or not isinstance(item.get("revision"), int)):
        return [f"{label} profile invalid"]
    try:
        key = base64.b64decode(item["public_key"], validate=True)
        signature = base64.b64decode(item["signature"], validate=True)
    except (ValueError, TypeError):
        return [f"{label} encoding invalid"]
    return [] if verify_ed25519(key, message_builder(item), signature) else [
        f"{label} signature invalid"
    ]


def verify(capsule: dict) -> list[str]:
    errors = []
    if not isinstance(capsule, dict):
        return ["capsule must be an object"]
    missing, unknown = REQUIRED - capsule.keys(), capsule.keys() - ALLOWED
    if missing:
        errors.append("missing fields: " + ", ".join(sorted(missing)))
    if unknown:
        errors.append("unknown fields: " + ", ".join(sorted(unknown)))
    if capsule.get("format") not in {ALPHA1, ALPHA2}:
        errors.append("unsupported format")
    if not isinstance(capsule.get("revision"), int) or capsule.get("revision", 0) < 1:
        errors.append("revision must be a positive integer")
    for field in ("claims", "evidence", "policy_results"):
        if not isinstance(capsule.get(field), list):
            errors.append(f"{field} must be an array")
    if isinstance(capsule.get("evidence"), list):
        for index, evidence in enumerate(capsule["evidence"]):
            reference = evidence.get("reference") if isinstance(evidence, dict) else None
            if reference is not None:
                required_reference = {"uri", "content_hash", "media_type", "disclosure"}
                if (not isinstance(reference, dict) or not required_reference <= reference.keys()
                    or reference.get("disclosure") not in {"private", "restricted", "public"}
                    or not isinstance(reference.get("content_hash"), str)
                    or len(reference["content_hash"]) != 71
                    or not reference["content_hash"].startswith("sha256:")):
                    errors.append(f"evidence[{index}] private reference invalid")
    integrity, computed = capsule.get("integrity"), content_hash(capsule)
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        errors.append("integrity.algorithm must be sha256")
    elif integrity.get("content_hash") != computed:
        errors.append("content hash mismatch")
    if capsule.get("format") == ALPHA2:
        for index, signature in enumerate(capsule.get("signatures", [])):
            errors += _verify_attestation(
                signature, signature_message, computed, f"signature[{index}]"
            )
        for index, approval in enumerate(capsule.get("approvals", [])):
            errors += _verify_attestation(
                approval, approval_message, computed, f"approval[{index}]"
            )
    elif capsule.get("signatures") or capsule.get("approvals"):
        errors.append("alpha.1 does not define signatures or approvals")
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

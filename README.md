# Evidence Capsule

Evidence Capsule is an open, portable format for sharing an AI-assisted
conclusion together with its material claims, evidence, assumptions, policy
results, provenance, revision history, and integrity information.

This repository contains the public specification, JSON Schema, test vectors,
and a dependency-free integrity verifier. It intentionally excludes Substrate's
hosted service, tenant management, private policy packs, and commercial control
plane.

Current version: `1.0.0-alpha.2`. The dependency-free verifier checks canonical
content hashes, Ed25519 author signatures, signed reviewer approvals, revision
identifiers, and privacy-preserving evidence references. Embedded public keys
prove control of a key; trusting that key as a real-world identity remains the
recipient's or a registry's responsibility. Alpha.1 integrity verification is
retained for backward compatibility.

```bash
python verifier/ecap_verify.py examples/minimal.ecap.json
python verifier/ecap_verify.py examples/signed-alpha2.ecap.json
```

The verifier exits non-zero when the capsule is malformed or its content hash
does not match its canonical unsigned payload.

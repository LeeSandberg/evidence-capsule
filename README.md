# Evidence Capsule

Evidence Capsule is an open, portable format for sharing an AI-assisted
conclusion together with its material claims, evidence, assumptions, policy
results, provenance, revision history, and integrity information.

This repository contains the public specification, JSON Schema, test vectors,
and a dependency-free integrity verifier. It intentionally excludes Substrate's
hosted service, tenant management, private policy packs, and commercial control
plane.

Current version: `1.0.0-alpha.1`. The alpha verifies canonical content hashes
and revision identifiers. Author and reviewer signature profiles are reserved
for the next compatible revision and must not yet be advertised as implemented.

```bash
python verifier/ecap_verify.py examples/minimal.ecap.json
```

The verifier exits non-zero when the capsule is malformed or its content hash
does not match its canonical unsigned payload.

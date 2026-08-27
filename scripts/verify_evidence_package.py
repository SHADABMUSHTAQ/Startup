"""Offline WarSOC evidence-package verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.utils.evidence_package import verify_evidence_package


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True, help="Extracted evidence package directory")
    parser.add_argument("--trusted-public-key", required=True, help="Trusted RSA public key PEM")
    args = parser.parse_args()

    result = verify_evidence_package(
        Path(args.package),
        Path(args.trusted_public_key).read_bytes(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("verified") else 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Modify the MKP extension manifest with version and metadata."""

import ast
import sys
from pathlib import Path
from pprint import pformat

PACKAGE_METADATA = {
    "author": "Felix Kraus (https://github.com/fxkraus)",
    "description": (
        "Monitors the expiration date of AWS IAM Identity Center SCIM access "
        "tokens using AWS Health events. Supports static access keys, the "
        "instance profile and Assume Role with an optional External ID."
    ),
    "download_url": "https://github.com/fxkraus/checkmk-special-agent-aws-scim-token/releases",
    "title": "AWS SCIM Token Monitor",
    "version.min_required": "2.4.0",
}


def update_manifest(manifest_path: Path, version: str) -> None:
    """Read the MKP manifest, inject metadata, and write it back."""
    # ast.literal_eval is safe — it only evaluates literal expressions.
    package_config = ast.literal_eval(manifest_path.read_text())

    package_config.update(PACKAGE_METADATA)
    package_config["version"] = version

    manifest_path.write_text(pformat(package_config, indent=4) + "\n")
    print(f"Manifest updated: version={version}")


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: build-modify-extension.py <version> <manifest-path>")
        sys.exit(1)

    version = sys.argv[1]
    manifest_path = Path(sys.argv[2])

    if not manifest_path.is_file():
        print(f"ERROR: Manifest file not found: {manifest_path}")
        sys.exit(1)

    update_manifest(manifest_path, version)


if __name__ == "__main__":
    main()

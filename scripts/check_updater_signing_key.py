#!/usr/bin/env python3
"""Validate the updater signing key without printing secret material."""

from __future__ import annotations

import base64
import binascii
import os
import sys


EXPECTED_HEADER = b"untrusted comment: rsign encrypted secret key"


def main() -> int:
    secret = os.environ.get("TAURI_SIGNING_PRIVATE_KEY")
    if not secret:
        print("TAURI_SIGNING_PRIVATE_KEY is not set", file=sys.stderr)
        return 1

    try:
        encoded = secret.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error):
        print(
            "TAURI_SIGNING_PRIVATE_KEY contains an invalid Base64 character; "
            "copy the key file directly without terminal prompt characters.",
            file=sys.stderr,
        )
        return 1

    lines = decoded.splitlines()
    if len(lines) != 2 or lines[0] != EXPECTED_HEADER or not lines[1]:
        print(
            "TAURI_SIGNING_PRIVATE_KEY is not a valid Tauri rsign private key.",
            file=sys.stderr,
        )
        return 1

    print("updater signing key format: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

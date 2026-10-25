# SPDX-License-Identifier: GPL-3.0-or-later
"""Regenerate the plist fixtures used by tests/plist_spec.rs.

The fixtures are written by CPython's plistlib, not by the `plist` crate, so the
Rust parser is checked against an independent implementation of the binary plist
format. The key names and value types mirror what upstream UxPlay reads and
writes:

* SETUP request/response      upstream/UxPlay/lib/raop_handlers.h:600-1067
* GET /info request/response  upstream/UxPlay/lib/raop_handlers.h:37-206

Usage:
  python tools/plist_fixtures.py                 # rewrite the fixtures
  python tools/plist_fixtures.py --verify FILE   # parse a plist with plistlib

The `--verify` form is also how the Rust encoder is cross-checked: the
integration test dumps what `Plist::encode_binary` produced into
$CARGO_TARGET_TMPDIR, and this script parses that file back.
"""

from __future__ import annotations

import argparse
import hashlib
import plistlib
import sys
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests/fixtures"

# A 64-bit stream connection id: real clients pick these at random, so the
# value deliberately exceeds i64::MAX to pin the unsigned-integer path.
STREAM_CONNECTION_ID = 12345678901234567890  # 2**63 < x < 2**64

SETUP_REQUEST = {
    "deviceID": "AA:BB:CC:DD:EE:FF",
    "model": "iPhone14,2",
    "name": "Tester's iPhone",
    "ekey": bytes(range(16)),
    "eiv": bytes(range(16, 32)),
    "streams": [
        {
            "type": 96,
            "controlPort": 6100,
            "ct": 2,
            "spf": 352,
            "audioFormat": 0x40000,
            "isMedia": False,
            "usingScreen": True,
        },
        {"type": 110, "streamConnectionID": STREAM_CONNECTION_ID},
    ],
}

SETUP_RESPONSE = {
    "timingPort": 7011,
    "eventPort": 0,
    "streams": [
        {"dataPort": 7100, "type": 110},
        {"dataPort": 7101, "controlPort": 7102, "type": 96},
    ],
}

INFO_REQUEST = {"qualifier": ["txtAirPlay"]}

INFO_RESPONSE = {
    "deviceID": "AA:BB:CC:DD:EE:FF",
    "macAddress": "AA:BB:CC:DD:EE:FF",
    "pk": bytes(range(32)),
    "features": 0x5A7FFFF7,
    "name": "Rust AirPlay",
    "pi": "b08f5a79-db29-4384-b456-a6f0e8e9d7db",
    "vv": 2,
    "statusFlags": 68,
    "keepAliveLowPower": 1,
    "sourceVersion": "220.68",
    "keepAliveSendStatsAsBody": True,
    "model": "AppleTV6,2",
    "initialVolume": 0.0,
    "audioLatencies": [
        {
            "type": 100,
            "inputLatencyMicros": 0,
            "audioType": "default",
            "outputLatencyMicros": 0,
        },
        {
            "type": 101,
            "inputLatencyMicros": 0,
            "audioType": "default",
            "outputLatencyMicros": 0,
        },
    ],
    "audioFormats": [
        {
            "audioInputFormats": 0x3FFFFFC,
            "audioOutputFormats": 0x3FFFFFC,
            "type": 100,
        }
    ],
}

FIXTURES = {
    "setup_request.bplist": SETUP_REQUEST,
    "setup_response.bplist": SETUP_RESPONSE,
    "info_request.bplist": INFO_REQUEST,
    "info_response.bplist": INFO_RESPONSE,
}


def write_fixtures() -> int:
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    for name, value in FIXTURES.items():
        payload = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
        path = FIXTURE_DIR / name
        path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        print(f"{name}: {len(payload)} bytes sha256={digest}")
    return 0


def verify(paths: list[str]) -> int:
    for raw in paths:
        path = Path(raw)
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        print(f"{path}: {len(payload)} bytes sha256={digest}")
        print(f"  plistlib: {plistlib.loads(payload)!r}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        nargs="+",
        metavar="FILE",
        help="parse plists with plistlib and print their contents",
    )
    args = parser.parse_args(argv)
    if args.verify:
        return verify(args.verify)
    return write_fixtures()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Command-line entry point.

Usage:
    python -m pgcap <client.bin> <server.bin> <output.json>

On success the JSON array is written atomically (temp file + replace),
so a pre-existing output file stays untouched on any protocol violation.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

from .framing import ProtocolViolation, frame_stream
from .protocol import correlate


def run(client_path: str, server_path: str, output_path: str) -> int:
    with open(client_path, "rb") as fh:
        client_bytes = fh.read()
    with open(server_path, "rb") as fh:
        server_bytes = fh.read()

    client_msgs = frame_stream(client_bytes, "client")
    server_msgs = frame_stream(server_bytes, "server")
    result = correlate(client_msgs, server_msgs)

    directory = os.path.dirname(os.path.abspath(output_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".pgcap-", suffix=".tmp",
                                    dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp_path, output_path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print("usage: python -m pgcap <client.bin> <server.bin> <output.json>",
              file=sys.stderr)
        return 64
    try:
        return run(argv[0], argv[1], argv[2])
    except ProtocolViolation as exc:
        # Whole-run rejection: report direction and zero-based start byte.
        detail = {
            "error": "protocol violation, run rejected",
            "direction": exc.direction,
            "offset": exc.offset,
            "reason": exc.reason,
        }
        print(json.dumps(detail, ensure_ascii=False), file=sys.stderr)
        return 1
    except OSError as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

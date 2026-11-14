#!/usr/bin/env bash
# Independent byte-level acceptance runner.
# Usage: ./run_acceptance.sh
set -euo pipefail
cd "$(dirname "$0")"
python3 -I tests/test_acceptance.py -v

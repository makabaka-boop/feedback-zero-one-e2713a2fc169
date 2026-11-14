#!/usr/bin/env python3
"""Executable entry point delegating to :mod:`pgcap.__main__`."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pgcap.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())

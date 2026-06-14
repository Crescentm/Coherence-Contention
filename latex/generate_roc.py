#!/usr/bin/env python3
"""Compatibility entrypoint for latex/picgen/generate_roc.py."""

from __future__ import annotations

import runpy
from pathlib import Path


if __name__ == "__main__":
    script_path = Path(__file__).resolve().parent / "picgen" / "generate_roc.py"
    runpy.run_path(str(script_path), run_name="__main__")

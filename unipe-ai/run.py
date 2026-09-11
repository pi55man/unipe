#!/usr/bin/env python3
"""Run the engine without installing the package."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unipe_ai.engine import main

if __name__ == "__main__":
    main()

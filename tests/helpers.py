"""Shared test helpers that keep temporary artifacts inside the repository."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Iterator


TESTS_DIR = Path(__file__).resolve().parent


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix="jlb-test-", dir=str(TESTS_DIR))

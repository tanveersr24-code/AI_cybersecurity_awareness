"""
tests/conftest.py — Shared pytest configuration.

Adds the project root to sys.path so all imports resolve correctly
regardless of how pytest is invoked.
"""

import sys
import os

# Insert the project root (one level above tests/) into the module search path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

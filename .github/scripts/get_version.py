#!/usr/bin/env python3
"""Extract version from mailmind package."""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from mailmind import __version__

print(__version__)

#!/usr/bin/env python3
"""
ShareCLI - Easy Local File Sharing
Usage: python3 run.py [options]
"""
import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.server import main

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
FileShare - Run this file to start the server
"""
import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.server import main

if __name__ == "__main__":
    main()

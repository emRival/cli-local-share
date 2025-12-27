#!/usr/bin/env python3
"""
Scam Check v2.0.0
OSINT Phone Lookup Tool

Run this file from the project root:
    python3 run.py
"""

import sys
import os

# Ensure we're in the right directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    try:
        from src.menu import main_loop
        main_loop()
    except KeyboardInterrupt:
        print("\n\n👋 Bye!")
        sys.exit(0)
    except ImportError as e:
        print(f"Error: Missing dependencies.")
        print(f"Run: pip3 install --break-system-packages -r requirements.txt")
        print(f"\nDetails: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

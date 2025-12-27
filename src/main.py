#!/usr/bin/env python3
"""
Scam Check v2.0.0
OSINT Phone Lookup Tool

Author: emRival
GitHub: github.com/emRival/scam-check
"""

import sys

def main():
    try:
        from src.menu import main_loop
        main_loop()
    except KeyboardInterrupt:
        print("\n\n👋 Bye!")
        sys.exit(0)
    except ImportError as e:
        print(f"Error: Missing dependencies. Please run: pip3 install -r requirements.txt")
        print(f"Details: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

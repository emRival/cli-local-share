# FileShare Makefile

.PHONY: install run clean help

help:
	@echo "FileShare - Simple File Sharing Server"
	@echo ""
	@echo "Commands:"
	@echo "  make install  - Install dependencies"
	@echo "  make run      - Run the server"
	@echo "  make clean    - Clean cache files"

install:
	@echo "[*] Installing dependencies..."
	@pip3 install --break-system-packages -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt
	@echo "[✓] Done!"

run:
	@python3 run.py

clean:
	@rm -rf __pycache__ src/__pycache__
	@echo "[✓] Cleaned!"

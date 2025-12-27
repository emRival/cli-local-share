# Scam Check v2 - Makefile
# Compatible with: Termux, Debian, Ubuntu

.PHONY: install install-deps run clean help

# Default target
help:
	@echo "Scam Check v2 - Available commands:"
	@echo "  make install    - Install all dependencies"
	@echo "  make run        - Run the application"
	@echo "  make clean      - Clean temporary files"

# Detect environment
detect:
	@if [ -d "/data/data/com.termux" ]; then \
		echo "termux" > .env_type; \
	else \
		echo "linux" > .env_type; \
	fi

# Install dependencies
install: detect
	@echo "[*] Installing dependencies..."
	@ENV_TYPE=$$(cat .env_type); \
	if [ "$$ENV_TYPE" = "termux" ]; then \
		pkg install -y python python-pip; \
	else \
		apt-get install -y python3 python3-pip 2>/dev/null || true; \
	fi
	@echo "[*] Installing Python packages..."
	@pip3 install --break-system-packages -r requirements.txt 2>/dev/null || \
		pip3 install -r requirements.txt 2>/dev/null || \
		pip install -r requirements.txt
	@echo "[✓] Installation complete!"

# Run the application
run:
	@python3 src/main.py 2>/dev/null || python src/main.py

# Clean temporary files
clean:
	@rm -rf __pycache__ src/__pycache__ src/modules/__pycache__
	@rm -f .env_type .os_type
	@echo "[✓] Cleaned!"

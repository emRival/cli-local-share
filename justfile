# Scam Check v2 - justfile

# Default recipe
default: run

# Install dependencies
install:
    @echo "[*] Installing dependencies..."
    pip3 install --break-system-packages -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt
    @echo "[✓] Done!"

# Run the application
run:
    @python3 src/main.py

# Clean temporary files
clean:
    rm -rf __pycache__ src/__pycache__ src/modules/__pycache__
    rm -f .env_type .os_type

# Show help
help:
    @echo "Scam Check v2"
    @echo "Commands: install, run, clean"

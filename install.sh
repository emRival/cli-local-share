#!/bin/bash

echo "🚀 Installing FileShare..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found."
    exit 1
fi

# Determine pip command
PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    if command -v pip &> /dev/null; then
        PIP_CMD="pip"
    else
        echo "❌ pip3 not found."
        exit 1
    fi
fi

# Install dependencies (rich only)
echo "📦 Installing dependencies..."
$PIP_CMD install -r requirements.txt --break-system-packages > /dev/null 2>&1 || $PIP_CMD install -r requirements.txt > /dev/null 2>&1

# Make run script executable
chmod +x run.py

echo "✅ Installation Complete!"
echo ""
echo "Type 'python3 run.py' to start the server."
echo "Or use 'make run' if you have make installed."

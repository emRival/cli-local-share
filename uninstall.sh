#!/bin/bash

# Configuration
APP_NAME="cli-local-share"
CONFIG_FILE="$HOME/.sharecli_config.json"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "\n${RED}🗑️  ShareCLI Uninstaller${NC}"
echo "--------------------------------"
echo -e "${YELLOW}Warning: This will remove:${NC}"
echo "1. The 'sharecli' command and package"
echo "2. All installed dependencies (rich, paramiko, etc.)"
echo "3. Configuration file ($CONFIG_FILE)"
echo "4. The entire repository directory ($(pwd))"
echo ""

read -p "Are you sure you want to uninstall? (y/N): " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
fi

echo -e "\n${YELLOW}⏳ Uninstalling python package...${NC}"
if command -v pip3 &> /dev/null; then
    pip3 uninstall -y $APP_NAME
else
    pip uninstall -y $APP_NAME
fi

echo -e "\n${YELLOW}⏳ Uninstalling dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    if command -v pip3 &> /dev/null; then
        pip3 uninstall -r requirements.txt -y
    else
        pip uninstall -r requirements.txt -y
    fi
fi

echo -e "\n${YELLOW}⏳ Removing configuration...${NC}"
rm -f "$CONFIG_FILE"

echo -e "\n${YELLOW}⏳ Removing alias...${NC}"
# Attempt to remove alias if manually added (optional, but good practice)
# We can't easily edit user's shell rc files safely without grep sed magic, 
# so we'll skip modifying .zshrc/.bashrc to avoid accidental damage.
# The 'sharecli' command was likely installed via pip entry_points anyway.

echo -e "\n${YELLOW}⏳ Removing files...${NC}"
# Get current directory
DIR=$(pwd)
# Change to parent directory
cd ..
# Remove the directory
rm -rf "$DIR"

echo -e "\n${GREEN}✅ Uninstall Complete!${NC}"
echo "Goodbye! 👋"

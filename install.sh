#!/bin/bash

# Configuration
REPO_URL="https://github.com/emRival/cli-local-share.git"
INSTALL_DIR="$HOME/cli-local-share"
BRANCH="main"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "🚀 Installing ShareCLI..."

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is required but not found.${NC}"
    exit 1
fi

# 2. Clone or Update Repository
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${BLUE}🔄 Updating existing installation in $INSTALL_DIR...${NC}"
    cd "$INSTALL_DIR"
    git pull origin $BRANCH >/dev/null 2>&1
else
    # Check if we are already IN the repo directory (ran locally)
    if [ -f "src/server.py" ]; then
        INSTALL_DIR=$(pwd)
        echo -e "${GREEN}✓ Running from local directory: $INSTALL_DIR${NC}"
    else
        echo -e "${BLUE}⬇️ Cloning repository to $INSTALL_DIR...${NC}"
        git clone -b $BRANCH $REPO_URL "$INSTALL_DIR" >/dev/null 2>&1
        cd "$INSTALL_DIR"
    fi
fi

# 3. Install Package (enables 'sharecli' command)
echo -e "${BLUE}📦 Installing application...${NC}"
PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_CMD="pip"
fi

# Install the current directory as a package
$PIP_CMD install . --break-system-packages > /dev/null 2>&1 || $PIP_CMD install . > /dev/null 2>&1

echo ""
echo -e "${GREEN}✅ Installation Complete!${NC}"
echo "------------------------------------------------"
echo -e "You can now run the server anywhere using:"
echo -e "${GREEN}sharecli${NC}"
echo "------------------------------------------------"

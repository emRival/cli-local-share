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

echo -e "${BLUE}🚀 FileShare Installer${NC}"

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

# 3. Install Dependencies
echo -e "${BLUE}📦 Installing dependencies...${NC}"
PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_CMD="pip"
fi

$PIP_CMD install -r requirements.txt --break-system-packages > /dev/null 2>&1 || $PIP_CMD install -r requirements.txt > /dev/null 2>&1

# 4. Finalize
chmod +x run.py

echo ""
echo -e "${GREEN}✅ Installation Complete!${NC}"
echo "------------------------------------------------"
echo -e "📂 Directory: ${BLUE}$INSTALL_DIR${NC}"
echo ""
echo "To start the server, run:"
echo -e "${GREEN}python3 $INSTALL_DIR/run.py${NC}"
echo "------------------------------------------------"

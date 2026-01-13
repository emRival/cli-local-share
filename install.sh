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

# 2. Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}❌ Git is required but not found. Please install git first.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Git found: $(git --version)${NC}"

# 3. Clone or Update Repository
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${BLUE}🔄 Updating existing installation in $INSTALL_DIR...${NC}"
    cd "$INSTALL_DIR" || {
        echo -e "${RED}❌ Failed to access $INSTALL_DIR${NC}"
        exit 1
    }
    if ! git pull origin $BRANCH > /dev/null 2>&1; then
        echo -e "${RED}❌ Failed to update repository${NC}"
        exit 1
    fi
else
    # Check if we are already IN the repo directory (ran locally)
    if [ -f "src/server.py" ]; then
        INSTALL_DIR=$(pwd)
        echo -e "${GREEN}✓ Running from local directory: $INSTALL_DIR${NC}"
    else
        echo -e "${BLUE}⬇️ Cloning repository to $INSTALL_DIR...${NC}"
        
        # Attempt to clone and capture the result
        if git clone -b $BRANCH $REPO_URL "$INSTALL_DIR" 2>&1; then
            echo -e "${GREEN}✓ Repository cloned successfully${NC}"
        else
            CLONE_EXIT_CODE=$?
            echo -e "${RED}❌ Failed to clone repository from $REPO_URL${NC}"
            echo -e "${RED}   Exit code: $CLONE_EXIT_CODE${NC}"
            echo -e "${RED}   Please check:${NC}"
            echo -e "${RED}   - Your internet connection${NC}"
            echo -e "${RED}   - Git is properly installed (try: git --version)${NC}"
            echo -e "${RED}   - You have access to GitHub${NC}"
            exit 1
        fi
        
        # Verify the directory was created
        if [ ! -d "$INSTALL_DIR" ]; then
            echo -e "${RED}❌ Clone appeared to succeed but directory $INSTALL_DIR was not created${NC}"
            exit 1
        fi
        
        cd "$INSTALL_DIR" || {
            echo -e "${RED}❌ Failed to access $INSTALL_DIR after cloning${NC}"
            exit 1
        }
    fi
fi

# 4. Install Package (enables 'sharecli' command)
echo -e "${BLUE}📦 Installing application...${NC}"
PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_CMD="pip"
fi

# Install the current directory as a package
$PIP_CMD install . --break-system-packages > /dev/null 2>&1 || $PIP_CMD install . > /dev/null 2>&1

echo ""
echo -e "\n${GREEN}✓ Installation complete!${NC}"
echo ""

# 5. Save install path to config for future updates
INSTALL_DIR="$(pwd)"
CONFIG_FILE="$HOME/.sharecli_config.json"

if [ -f "$CONFIG_FILE" ]; then
    # Update existing config with install_path using Python
    python3 -c "import json; config=json.load(open('$CONFIG_FILE')); config['install_path']='$INSTALL_DIR'; json.dump(config, open('$CONFIG_FILE', 'w'), indent=4)" 2>/dev/null || true
else
    # Create new config with install_path
    echo "{\"install_path\": \"$INSTALL_DIR\"}" > "$CONFIG_FILE"
fi

echo -e "${BLUE}Run '${GREEN}sharecli${BLUE}' to start the application${NC}"
echo ""

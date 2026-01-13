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

# Check for pip/pip3
PIP_CMD=""
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
else
    echo -e "${RED}❌ pip is not installed. Please install Python pip:${NC}"
    echo -e "${RED}   sudo apt install python3-pip${NC}"
    exit 1
fi

echo -e "${BLUE}Using: $PIP_CMD install${NC}"

# Try to install with --break-system-packages (for newer systems), fallback to regular install
echo -e "${BLUE}Attempting installation with --break-system-packages...${NC}"
$PIP_CMD install . --break-system-packages 2>&1 | tee /tmp/sharecli_install.log
INSTALL_STATUS=${PIPESTATUS[0]}

if [ $INSTALL_STATUS -ne 0 ]; then
    echo -e "${BLUE}Retrying without --break-system-packages...${NC}"
    $PIP_CMD install . 2>&1 | tee /tmp/sharecli_install.log
    INSTALL_STATUS=${PIPESTATUS[0]}
fi

if [ $INSTALL_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ Package installed successfully${NC}"
else
    echo -e "${RED}❌ Failed to install package (exit code: $INSTALL_STATUS)${NC}"
    echo -e "${RED}Installation log saved to: /tmp/sharecli_install.log${NC}"
    echo ""
    echo -e "${RED}Common issues:${NC}"
    echo -e "${RED}  - Missing pip: sudo apt install python3-pip${NC}"
    echo -e "${RED}  - Permission issues: try adding --user flag${NC}"
    echo -e "${RED}  - Check the log file for details${NC}"
    exit 1
fi

# Detect where the script was installed
USER_BIN="$HOME/.local/bin"
if [ -d "$USER_BIN" ] && [ -f "$USER_BIN/sharecli" ]; then
    SCRIPT_LOCATION="$USER_BIN/sharecli"
else
    # Try to find it
    SCRIPT_LOCATION=$(which sharecli 2>/dev/null || find ~/.local/bin /usr/local/bin -name "sharecli" 2>/dev/null | head -n 1)
fi

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""

# Check if sharecli is in PATH
if command -v sharecli &> /dev/null; then
    echo -e "${GREEN}✓ 'sharecli' command is ready to use!${NC}"
else
    echo -e "${BLUE}⚠️  The 'sharecli' command is not in your PATH${NC}"
    if [ -n "$SCRIPT_LOCATION" ]; then
        echo -e "${BLUE}   Script installed at: $SCRIPT_LOCATION${NC}"
    fi
    echo -e "${BLUE}   Add this to your ~/.bashrc or ~/.zshrc:${NC}"
    echo -e "${GREEN}   export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    echo ""
    echo -e "${BLUE}   Then run: ${GREEN}source ~/.bashrc${NC} ${BLUE}(or logout and login)${NC}"
    echo ""
    echo -e "${BLUE}   Or run directly: ${GREEN}$HOME/.local/bin/sharecli${NC}"
fi
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

import json
import os
from typing import Dict, Any

CONFIG_FILE = os.path.expanduser("~/.sharecli_config.json")

DEFAULT_CONFIG = {
    "last_directory": os.getcwd(),
    "port": 8080,
    "use_https": True,
    "auth_choice": "1",  # 1=Token, 2=Password, 3=None
    "timeout": 30,
    "enable_sftp": False,
    "sftp_port": 2222
}

def load_config() -> Dict[str, Any]:
    """Load configuration from JSON file"""
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # Merge with default to ensure all keys exist
            final_config = DEFAULT_CONFIG.copy()
            final_config.update(config)
            return final_config
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(config: Dict[str, Any]):
    """Save configuration to JSON file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        pass  # Fail silently if cannot save config

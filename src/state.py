from typing import List, Dict, Set
from collections import defaultdict
from datetime import datetime
import threading

# Global state
ACCESS_LOG: List[Dict] = []
SERVER_RUNNING = False
BLOCKED_IPS: Dict[str, datetime] = {}
FAILED_ATTEMPTS: Dict[str, int] = defaultdict(int)
WHITELIST_IPS: Set[str] = set()
STATE_LOCK = threading.Lock()

# Security settings
MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION_SECONDS = 300  # 5 minutes
SYSTEM_USERNAME = ""
SESSION_ID = datetime.now().strftime("%H%M%S") # Unique per session

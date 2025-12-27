import os
import sys
import socket
import subprocess
import time
import ipaddress
from typing import Optional, List, Dict
from rich.console import Console
from rich.prompt import Prompt

console = Console()

def get_system_username() -> str:
    """Get system username"""
    import getpass
    try:
        return getpass.getuser()
    except:
        return "user"


def get_local_ip() -> str:
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def get_network_range() -> str:
    """Get network range (e.g., 192.168.1.0/24)"""
    local_ip = get_local_ip()
    parts = local_ip.split('.')
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def format_size(size_bytes):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"





def ask_robust_int(prompt_text, default=None):
    """
    Ask for an integer input robustly, handling ANSI escape codes 
    (like arrow keys) that might crash simple int() conversions.
    """
    while True:
        val_input = Prompt.ask(prompt_text, default=default)
        
        if val_input is None:
            console.print("[red]❌ Invalid input. Please enter a number.[/red]")
            continue
        
        # Remove ANSI escape codes if present (rudimentary check)
        # Better: remove all non-digits
        clean_input = "".join(filter(str.isdigit, str(val_input)))
        
        if not clean_input:
            console.print("[red]❌ Invalid input. Please enter a number.[/red]")
            continue
            
        try:
            return int(clean_input)
        except ValueError:
            console.print("[red]❌ Invalid input. Please enter a number.[/red]")


def check_updates() -> bool:
    """Check if updates are available"""
    try:
        subprocess.run(["git", "fetch"], check=True, capture_output=True)
        result = subprocess.run(
            ["git", "status", "-uno"], 
            check=True, 
            capture_output=True, 
            text=True
        )
        return "Your branch is behind" in result.stdout
    except:
        return False


def update_tool():
    """Update the tool from git"""
    console.print("\n[yellow]📦 Checking for updates...[/yellow]")
    
    try:
        # Check remote
        subprocess.run(["git", "fetch"], check=True, capture_output=True)
        
        # Check status
        status = subprocess.run(
            ["git", "status", "-uno"], 
            check=True, 
            capture_output=True, 
            text=True
        )
        
        if "Your branch is behind" in status.stdout:
            console.print("[green]✨ Update available! Installing...[/green]")
            subprocess.run(["git", "pull"], check=True)
            console.print("[green]✅ Update successful! Restarting...[/green]")
            time.sleep(1)
            
            # Restart script
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            console.print("[green]✅ You are using the latest version![/green]")
            time.sleep(1)
            
    except Exception as e:
        console.print(f"[red]❌ Update failed: {e}[/red]")
        console.print("[yellow]Please try 'git pull' manually.[/yellow]")
        input("\nPress Enter to continue...")

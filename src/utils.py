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
    """Update the tool from git and reinstall dependencies"""
    console.print("\n[yellow]📦 Checking for updates...[/yellow]")
    
    try:
        # Get script directory
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Check remote
        subprocess.run(["git", "fetch"], check=True, capture_output=True, cwd=script_dir)
        
        # Check status
        status = subprocess.run(
            ["git", "status", "-uno"], 
            check=True, 
            capture_output=True, 
            text=True,
            cwd=script_dir
        )
        
        if "Your branch is behind" in status.stdout:
            console.print("[green]✨ Update available! Downloading...[/green]")
            
            # Pull latest code
            subprocess.run(["git", "pull"], check=True, cwd=script_dir)
            console.print("[green]✅ Code updated![/green]")
            
            # Reinstall dependencies
            console.print("[yellow]📦 Updating dependencies...[/yellow]")
            req_file = os.path.join(script_dir, "requirements.txt")
            if os.path.exists(req_file):
                try:
                    # Try with --break-system-packages first (for newer pip)
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "-r", req_file, 
                         "--break-system-packages", "--quiet"],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode != 0:
                        # Fallback without --break-system-packages
                        subprocess.run(
                            [sys.executable, "-m", "pip", "install", "-r", req_file, "--quiet"],
                            check=True
                        )
                    console.print("[green]✅ Dependencies updated![/green]")
                except Exception as e:
                    console.print(f"[yellow]⚠️ Dependency update failed: {e}[/yellow]")
                    console.print("[dim]You may need to run: pip install -r requirements.txt[/dim]")
            
            console.print("\n[green]🎉 Update complete! Restarting...[/green]")
            time.sleep(1)
            
            # Restart script
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            console.print("[green]✅ You are using the latest version![/green]")
            time.sleep(1)
            
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Update failed: {e}[/red]")
        console.print("[yellow]Please try 'git pull' manually.[/yellow]")
        input("\nPress Enter to continue...")
    except Exception as e:
        console.print(f"[red]❌ Update failed: {e}[/red]")
        input("\nPress Enter to continue...")


def uninstall_tool():
    """Uninstall the tool and dependencies"""
    console.print("\n[red]🗑️  ShareCLI Uninstaller[/red]")
    console.print("--------------------------------")
    console.print("[yellow]Warning: This will remove:[/yellow]")
    console.print("1. The 'sharecli' command and package")
    console.print("2. Installed dependencies (rich, qrcode, paramiko, sftpserver)")
    console.print("3. Configuration file (~/.sharecli_config.json)")
    
    confirm = Prompt.ask("\nAre you sure you want to uninstall?", choices=["y", "n"], default="n")
    if confirm != "y":
        console.print("Aborted.")
        return

    try:
        # 1. Uninstall Dependencies
        console.print("\n[yellow]⏳ Uninstalling dependencies...[/yellow]")
        deps = ["rich", "qrcode", "paramiko", "sftpserver"]
        subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "-y"] + deps,
            check=False
        )
        
        # 2. Remove Config
        console.print("\n[yellow]⏳ Removing configuration...[/yellow]")
        config_path = os.path.expanduser("~/.sharecli_config.json")
        if os.path.exists(config_path):
            os.remove(config_path)
            
        # 3. Uninstall Package
        console.print("\n[yellow]⏳ Uninstalling sharecli...[/yellow]")
        subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "-y", "cli-local-share"],
            check=False
        )
        
        console.print("\n[green]✅ Uninstall Complete![/green]")
        console.print("To remove the source files, please delete this directory manually.")
        
    except Exception as e:
        console.print(f"\n[red]❌ Uninstall failed: {e}[/red]")

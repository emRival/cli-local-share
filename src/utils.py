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
    """Check and install updates from GitHub"""
    console.print("\n[cyan]📦 Checking for updates...[/cyan]")
    
    try:
        from src.config import load_config
        
        # Determine git repository directory
        current_dir = os.getcwd()
        git_dir = current_dir
        
        # Check if current directory is a git repo
        if not os.path.exists(os.path.join(current_dir, '.git')):
            # Load install path from config
            config = load_config()
            install_path = config.get('install_path', '')
            
            if not install_path or not os.path.exists(install_path):
                console.print("[red]❌ Update failed: Installation path not found.[/red]")
                console.print("[yellow]Please run update manually with:[/yellow]")
                console.print("cd /path/to/cli-local-share && git pull && pip3 install . --upgrade --break-system-packages")
                input("\nPress Enter to continue...")
                return
            
            git_dir = install_path
            console.print(f"[dim]Using install path: {git_dir}[/dim]")
        
        # Change to git directory
        os.chdir(git_dir)
        
        # Fetch latest changes
        subprocess.run(['git', 'fetch'], check=True, capture_output=True)
        
        # Check if there are updates
        result = subprocess.run(
            ['git', 'rev-list', 'HEAD...origin/main', '--count'],
            capture_output=True,
            text=True,
            check=True
        )
        
        updates_count = int(result.stdout.strip())
        
        if updates_count == 0:
            console.print("[green]✓ Already up to date![/green]")
            input("\nPress Enter to continue...")
            os.chdir(current_dir)  # Return to original directory
            return
        
        console.print(f"[yellow]Found {updates_count} update(s). Pulling changes...[/yellow]")
        
        # Pull updates
        subprocess.run(['git', 'pull'], check=True, capture_output=True)
        
        console.print("[cyan]📦 Reinstalling package and dependencies...[/cyan]")
        
        # Reinstall package with dependencies
        try:
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '.', '--upgrade', '--break-system-packages'],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError:
            # Fallback without --break-system-packages
            subprocess.run(
                [sys.executable, '-m', 'pip', 'install', '.', '--upgrade'],
                check=True,
                capture_output=True
            )
        
        console.print("[green]✓ Update complete! Restarting...[/green]")
        time.sleep(1)
        
        # Restart the application
        os.chdir(current_dir)  # Return to original directory before restarting
        os.execv(sys.executable, [sys.executable] + sys.argv)
        
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Update failed: {e}[/red]")
        console.print("[yellow]Please try 'git pull' manually.[/yellow]")
        input("\nPress Enter to continue...")
        if 'git_dir' in locals() and git_dir != current_dir:
            os.chdir(current_dir)  # Return to original directory
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}[/red]")
        input("\nPress Enter to continue...")
        if 'git_dir' in locals() and git_dir != current_dir:
            os.chdir(current_dir)  # Return to original directory


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

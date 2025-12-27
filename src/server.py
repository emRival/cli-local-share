#!/usr/bin/env python3
"""
FileShare v2.5 - Secure File Sharing Server
Refactored Modular Architecture

Components:
- src/state.py: Global state and constants
- src/utils.py: Helper functions
- src/security.py: Auth and Network security
- src/handler.py: HTTP Request Handler
- src/ui.py: Rich Terminal Interface
"""

import sys
import os

try:
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
except ImportError:
    print("Installing dependencies...")
    os.system("pip3 install --break-system-packages rich qrcode Pillow 2>/dev/null || pip3 install rich qrcode Pillow")
    from rich.console import Console
    from rich.prompt import Prompt, Confirm

# Import modular components
from src.utils import get_system_username, ask_robust_int, check_updates, update_tool
from src.security import setup_whitelist
from src.ui import print_banner, run_server_with_ui, browse_directory
from src.handler import SecureAuthHandler 
# Note: SecureAuthHandler is imported but used dynamically in ui.py or main logic if needed, 
# but run_server_with_ui handles the server creation.

# Try importing config, handle if missing
try:
    from src.config import load_config, save_config
except ImportError:
    def load_config(): return {}
    def save_config(c): pass

console = Console()

def main():
    """Main setup wizard"""
    try:
        console.clear()
        print_banner()
        
        # Load config
        config = load_config()
        default_dir = config.get("last_directory", os.getcwd())
        if not os.path.isdir(default_dir):
            default_dir = os.getcwd()

        console.print("\n[bold cyan]📁 FILE SHARE SETUP[/bold cyan]\n")
        
        # Directory selection
        console.print(f"[yellow]Directory to share:[/yellow]")
        console.print("  [cyan]1[/cyan] - Browse (interactive file browser)")
        console.print("  [cyan]2[/cyan] - Type path manually")
        console.print("  [cyan]3[/cyan] - Use current directory")
        console.print("  [cyan]u[/cyan] - Check for updates\n")
        
        dir_choice = Prompt.ask("Choice", choices=["1", "2", "3", "u"], default="1")
        
        if dir_choice == "u":
            update_tool()
            return
        elif dir_choice == "1":
            directory = browse_directory()
        elif dir_choice == "2":
            directory = input("Path> ").strip()
            if not directory:
                directory = os.getcwd()
        else:
            directory = os.getcwd()
        
        if not os.path.isdir(directory):
            console.print("[red]Error: Directory not found![/red]")
            return
        
        console.print(f"\n[green]✓ Selected: {directory}[/green]\n")
        
        # Port
        while True:
            port = ask_robust_int("[yellow]Port[/yellow]", default="8080")
            
            if port < 1024 or port > 65535:
                console.print("[red]❌ Port must be between 1024 and 65535[/red]")
                continue
            
            # Check if port is in use (We need to import this check or re-implement)
            from src.server import is_port_in_use  # Circular dependency risk if we keep it here
            # Better: move is_port_in_use to utils
            if is_port_in_use(port):
                console.print(f"[red]❌ Port {port} is already in use by another application![/red]")
                console.print("[yellow]Please choose a different port.[/yellow]")
            else:
                break
        
        # HTTPS
        use_https = Confirm.ask("[yellow]Enable HTTPS?[/yellow]", default=True)
        
        # Authentication - choose ONE method
        console.print("[yellow]Authentication method:[/yellow]")
        console.print("  [cyan]1[/cyan] - Token (recommended, auto-generated secure token)")
        console.print("  [cyan]2[/cyan] - Password (set your own password)")
        console.print("  [cyan]3[/cyan] - None (public access, risky!)")
        
        auth_choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="1")
        
        sys_user = get_system_username()
        
        password = None
        token = None
        
        if auth_choice == "1":
            import secrets
            token = secrets.token_urlsafe(16)
            console.print(f"\n[green]✓ Generated secure token[/green]")
        elif auth_choice == "2":
            while True:
                password = Prompt.ask("Set Password", password=True)
                if len(password) < 4:
                    console.print("[red]Password too short![/red]")
                else:
                    break
        else:
            console.print("[yellow]⚠️ No authentication - anyone can access![/yellow]\n")
        
        # Timeout
        timeout = ask_robust_int("[yellow]Session timeout (minutes, 0=unlimited)[/yellow]", default="30")
        
        # Save config
        new_config = {
            "last_directory": directory,
            "port": port,
            "use_https": use_https,
            "auth_choice": auth_choice,
            "timeout": timeout
        }
        save_config(new_config)
        
        # Whitelist
        setup_whitelist()
        
        # Start Server
        run_server_with_ui(port, directory, password, token, timeout, use_https)
            
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Fatal Error: {e}[/red]")
        import traceback
        traceback.print_exc()

def is_port_in_use(port: int) -> bool:
    """Check if port is already in use"""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

if __name__ == '__main__':
    main()

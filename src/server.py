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
        
        if not os.path.exists('access.log'):
            with open('access.log', 'w') as f:
                f.write('')
        
        # Load config
        config = load_config()
        default_dir = config.get("last_directory", os.getcwd())
        default_port = str(config.get("port", "8080"))
        default_https = config.get("use_https", True)
        default_auth = config.get("auth_choice", "1")
        default_timeout = str(config.get("timeout", "30"))
        default_upload = config.get("allow_upload", False)
        default_remove = config.get("allow_remove", False)
        
        if not os.path.isdir(default_dir):
            default_dir = os.getcwd()

        console.print("\n[bold cyan]📁 FILE SHARE SETUP[/bold cyan]\n")
        
        directory = None
        while directory is None:
            # Directory selection
            console.print(f"[yellow]Directory to share:[/yellow]")
            console.print("  [cyan]1[/cyan] - Browse (interactive file browser)")
            console.print("  [cyan]2[/cyan] - Type path manually")
            console.print("  [cyan]3[/cyan] - Use current directory")
            console.print("  [cyan]u[/cyan] - Check for updates\n")
            
            dir_choice = Prompt.ask("Choice", choices=["1", "2", "3", "u"], default="1")
            
            if dir_choice == "u":
                update_tool()
                # Continue loop to show menu again
                console.print("\n")
                continue
            elif dir_choice == "1":
                directory = browse_directory()
            elif dir_choice == "2":
                directory = input("Path> ").strip()
                if not directory:
                    directory = os.getcwd()
            else:
                directory = default_dir if dir_choice == "3" and default_dir == os.getcwd() else os.getcwd()
            
            if not os.path.isdir(directory):
                console.print("[red]Error: Directory not found![/red]")
                directory = None # Loop again
        
        console.print(f"\n[green]✓ Selected: {directory}[/green]\n")
        
        # Port with Loop for conflict
        port_ok = False
        port = int(default_port)
        
        while not port_ok:
            port = ask_robust_int("[yellow]Port[/yellow]", default=str(port))
            
            if port < 1024 or port > 65535:
                console.print("[red]❌ Port must be between 1024 and 65535[/red]")
                continue
            
            if is_port_in_use(port):
                console.print(f"[red]❌ Port {port} is already in use![/red]")
                console.print("[yellow]Please choose a different port.[/yellow]")
                # Suggest next port
                port += 1
                continue
            else:
                port_ok = True
        
        # HTTPS
        use_https = Confirm.ask("[yellow]Enable HTTPS?[/yellow]", default=default_https)
        
        # Authentication - choose ONE method
        console.print("[yellow]Authentication method:[/yellow]")
        console.print("  [cyan]1[/cyan] - Token (recommended, auto-generated secure token)")
        console.print("  [cyan]2[/cyan] - Password (set your own password)")
        console.print("  [cyan]3[/cyan] - None (public access, risky!)")
        
        auth_choice = Prompt.ask("Choice", choices=["1", "2", "3"], default=default_auth)
        
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
        timeout = ask_robust_int("[yellow]Session timeout (minutes, 0=unlimited)[/yellow]", default=default_timeout)
        
        # Permissions
        console.print("")
        allow_upload = Confirm.ask("[yellow]Enable File Upload?[/yellow] (Allows visitors to upload files)", default=default_upload)
        allow_remove = Confirm.ask("[yellow]Enable File Deletion? [/yellow] [red](WARNING: Visitors can delete files!)[/red]", default=default_remove)

        # Save config BEFORE starting server
        try:
            new_config = {
                "last_directory": directory,
                "port": port,
                "use_https": use_https,
                "auth_choice": auth_choice,
                "timeout": timeout,
                "allow_upload": allow_upload,
                "allow_remove": allow_remove
            }
            save_config(new_config)
            # console.print("[dim]Configuration saved.[/dim]")
        except Exception as e:
            pass
        
        # Whitelist
        setup_whitelist()
        
        # Start Server
        run_server_with_ui(port, directory, password, token, timeout, use_https, allow_upload, allow_remove)
            
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
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

if __name__ == '__main__':
    main()

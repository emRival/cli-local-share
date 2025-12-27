import os
import time
import socket
import socketserver
import ssl
import threading
from functools import partial
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.align import Align
from rich.prompt import Prompt

from src.state import SERVER_RUNNING, ACCESS_LOG, BLOCKED_IPS, FAILED_ATTEMPTS, WHITELIST_IPS, BLOCK_DURATION_SECONDS
from src.utils import get_system_username, get_local_ip, format_size, ask_robust_int
from src.handler import SecureAuthHandler
from src.security import generate_self_signed_cert

console = Console()

def print_banner():
    """Print application banner"""
    banner = """
[bold cyan]╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   [bold white]███████╗██╗██╗     ███████╗[/bold white]                            ║
║   [bold white]██╔════╝██║██║     ██╔════╝[/bold white]                            ║
║   [bold white]█████╗  ██║██║     █████╗  [/bold white]                            ║
║   [bold white]██╔══╝  ██║██║     ██╔══╝  [/bold white]                            ║
║   [bold white]██║     ██║███████╗███████╗[/bold white]                            ║
║   [bold white]╚═╝     ╚═╝╚══════╝╚══════╝[/bold white]                            ║
║                                                           ║
║   [bold green]SHARE[/bold green] v2.0 - Secure File Sharing                       ║
║   [dim]🔒 HTTPS • 🛡️ Rate Limit • 📋 IP Whitelist[/dim]             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(banner)


def create_status_display(url: str, directory: str, password: str, token: str, 
                          timeout: int, use_https: bool, qr_text: str):
    """Create status display"""
    # Use explicit width for stability
    info_table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2), expand=True, border_style="blue")
    info_table.add_column("Key", style="cyan", width=12)
    info_table.add_column("Value", style="white")
    
    protocol = "[bold green]🔒 HTTPS[/bold green]" if use_https else "[yellow]⚠️ HTTP[/yellow]"
    info_table.add_row("👤 User", f"[bold]{get_system_username()}[/bold]")
    info_table.add_row("🌐 URL", f"[bold]{url}[/bold]")
    info_table.add_row("🔐 Protocol", protocol)
    info_table.add_row("📁 Directory", directory[:30])
    info_table.add_row("⏱️  Timeout", f"{timeout}m" if timeout > 0 else "∞")
    info_table.add_row("🛡️ Rate Limit", f"Max 5 attempts / {BLOCK_DURATION_SECONDS}s ban")
    
    auth_status = []
    if password: auth_status.append("Password")
    if token: auth_status.append("Token")
    if not password and not token: auth_status.append("None")
    info_table.add_row("🔑 Auth", ", ".join(auth_status))
    
    # Show full token if present, wrapping if needed
    if token:
        info_table.add_row("🎫 Token", f"[bold]{token}[/bold]")

    # Files
    files = []
    try:
        for f in os.listdir(directory)[:8]:
            path = os.path.join(directory, f)
            if os.path.isfile(path):
                size = format_size(os.path.getsize(path))
                files.append(f"📄 {f[:25]} ({size})")
            else:
                files.append(f"📁 {f[:25]}/")
    except:
        files = ["[dim]Cannot read[/dim]"]
    
    files_text = "\n".join(files)
    
    return info_table, files_text, None


def create_log_display():
    """Create access log display"""
    if not ACCESS_LOG:
        return "[dim]No access yet...[/dim]"
    
    log_table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1), expand=True)
    log_table.add_column("Time", style="dim", width=10)
    log_table.add_column("IP", style="cyan", width=15)
    log_table.add_column("Status", width=15)
    log_table.add_column("Path", style="dim", width=25)
    
    for log in ACCESS_LOG[-8:]:
        path = log.get("path", "-")
        # Truncate path if too long
        if len(path) > 23:
            path = path[:20] + "..."
        log_table.add_row(log["time"], log["ip"], log["status"], path)
    
    return log_table


def browse_directory() -> str:
    """Interactive directory browser"""
    current_dir = os.getcwd()
    
    while True:
        console.clear()
        console.print(f"\n[bold cyan]📂 DIRECTORY BROWSER[/bold cyan]\n")
        console.print(f"[dim]Current: {current_dir}[/dim]\n")
        
        # List contents
        items = []
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    if entry.is_dir() and not entry.name.startswith('.'):
                        items.append(entry.name)
        except PermissionError:
            console.print("[red]Permission denied![/red]")
            time.sleep(1)
            current_dir = os.path.dirname(current_dir)
            continue
            
        items.sort()
        items.insert(0, "..")
        items.append("[Done: Select this folder]")
        
        # Display pagination
        for i, item in enumerate(items):
            prefix = "📁 " if item not in ["..", "[Done: Select this folder]"] else ""
            console.print(f"[cyan]{i+1}[/cyan]. {prefix}{item}")
            
        console.print("\n[yellow]Enter number to navigate/select:[/yellow]")
        
        from src.utils import ask_robust_int
        choice = ask_robust_int("> ")
        
        if 1 <= choice <= len(items):
            selected = items[choice-1]
            if selected == "..":
                current_dir = os.path.dirname(current_dir)
            elif selected == "[Done: Select this folder]":
                return current_dir
            else:
                current_dir = os.path.join(current_dir, selected)


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def create_server(port: int, directory: str, password: str = None, token: str = None, use_https: bool = False, allow_upload: bool = False, allow_remove: bool = False):
    """Create HTTP/HTTPS server"""
    handler = partial(SecureAuthHandler, password=password, token=token, directory=directory, allow_upload=allow_upload, allow_remove=allow_remove)
    server = ReusableTCPServer(("", port), handler)
    
    if use_https:
        cert_file = "/tmp/fileshare_cert.pem"
        key_file = "/tmp/fileshare_key.pem"
        
        if generate_self_signed_cert(cert_file, key_file):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_file, key_file)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            return server, True
        else:
            console.print("[yellow]⚠️ HTTPS tidak tersedia, menggunakan HTTP[/yellow]")
            return server, False
    
    return server, False


def run_server_with_ui(port: int, directory: str, password: str, token: str, 
                        timeout: int, use_https: bool, allow_upload: bool = False, allow_remove: bool = False):
    """Run server with live UI"""
    
    import src.state as state
    
    state.ACCESS_LOG.clear()
    state.BLOCKED_IPS.clear()
    state.FAILED_ATTEMPTS.clear()
    state.SERVER_RUNNING = True
    
    ip = get_local_ip()
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}:{port}"
    
    try:
        server, https_enabled = create_server(port, directory, password, token, use_https, allow_upload, allow_remove)
        if use_https and not https_enabled:
            url = f"http://{ip}:{port}"
    except OSError as e:
        console.print(f"[red]Error: Port {port} already in use![/red]")
        return
    
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    start_time = datetime.now()
    end_time = start_time + timedelta(minutes=timeout) if timeout > 0 else None
    
    console.clear()
    
    try:
        # Hide cursor for cleaner display
        console.show_cursor(False)
        with Live(console=console, refresh_per_second=4, screen=True) as live:
            while state.SERVER_RUNNING:
                if end_time and datetime.now() >= end_time:
                    console.print("\n[yellow]⏱️ Session timeout![/yellow]")
                    break
                
                if end_time:
                    remaining = end_time - datetime.now()
                    remaining_str = f"{int(remaining.total_seconds() // 60)}m {int(remaining.total_seconds() % 60)}s"
                else:
                    remaining_str = "∞"
                
                layout = Layout()
                layout.split_column(
                    Layout(name="header", size=3),
                    Layout(name="main"),
                    Layout(name="footer", size=3)
                )
                layout = Layout()
                layout.split_column(
                    Layout(name="header", size=3),
                    Layout(name="main"),
                    Layout(name="footer", size=3)
                )

                # Header with Large URL
                header_text = Text()
                header_text.append(f"🔗 {url}", style="bold cyan")
                header_text.append("  |  ", style="dim")
                header_text.append("📡 Server Running", style="bold green")
                layout["header"].update(Panel(header_text, box=box.ROUNDED, style="blue"))
                
                # Main Content (Full Width)
                # Combine info and log into one view or simple vertical split if needed
                # User wants "cleaner", so maybe just Log and minimal status
                
                info_table, files_text, _ = create_status_display(
                    url, directory, password, token, timeout, https_enabled, ""
                )
                
                main_grid = Table.grid(padding=1, expand=True)
                main_grid.add_column(ratio=1)
                main_grid.add_row(Panel(info_table, title="📋 Info", border_style="cyan", box=box.ROUNDED))
                main_grid.add_row(Panel(state.ACCESS_LOG_GROUP, title=f"📊 Live Access Log ({len(state.ACCESS_LOG)})", border_style="green", box=box.ROUNDED))

                layout["main"].update(main_grid)
                
                layout["footer"].update(Panel(
                    "[bold red]Press Ctrl+C to stop server[/bold red]",
                    box=box.ROUNDED,
                    style="on black"
                ))
                
                live.update(layout)
                time.sleep(0.25)
                
    except KeyboardInterrupt:
        pass
    finally:
        console.show_cursor(True)
        state.SERVER_RUNNING = False
        try:
            server.shutdown()
            server.server_close()  # Release port immediately
        except:
            pass
        console.print("\n[cyan]👋 Server stopped.[/cyan]\n")

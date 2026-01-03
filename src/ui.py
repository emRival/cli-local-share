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

from src.state import SERVER_RUNNING, ACCESS_LOG, BLOCKED_IPS, FAILED_ATTEMPTS, WHITELIST_IPS, BLOCK_DURATION_SECONDS, STATE_LOCK
from src.utils import get_system_username, get_local_ip, format_size, ask_robust_int
from src.handler import SecureAuthHandler
from src.security import generate_self_signed_cert

console = Console()

def print_banner():
    """Print application banner using Rich Panel"""
    title = Text("SHARE v2.5", style="bold green")
    subtitle = Text("Secure File Sharing", style="bold white")
    
    content = Align.center(
        Text.assemble(
            title, " - ", subtitle, "\n",
            Text("🔒 HTTPS • 🛡️ Rate Limit • 📋 IP Whitelist", style="dim cyan"),
        )
    )
    
    console.print(Panel(
        content,
        box=box.DOUBLE,
        border_style="cyan",
        expand=False,
        padding=(1, 2)
    ))







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
        last_file_update = 0
        files_text = ""
        
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
                
                # Build Clean Dashboard Layout
                layout = Layout()
                layout.split_column(
                    Layout(name="header", size=3),
                    Layout(name="body"),
                    Layout(name="footer", size=3)
                )
                
                # === HEADER: URL + Status + Countdown ===
                header_text = Text()
                header_text.append("🔗 ", style="bold")
                header_text.append(url, style="bold cyan underline")
                header_text.append("  │  ", style="dim")
                header_text.append("📡 Running", style="bold green")
                header_text.append("  │  ", style="dim")
                header_text.append(f"⏱️ {remaining_str}", style="bold yellow")
                
                # Single Main Panel for everything to keep borders consistent
                main_grid = Table.grid(expand=True)
                main_grid.add_column()
                
                # Rows for header, info, log, files
                main_grid.add_row(Align.center(header_text))
                main_grid.add_row("") # Spacer
                
                # Info + Log Table
                top_table = Table.grid(expand=True, padding=(0, 2))
                top_table.add_column(ratio=1)
                top_table.add_column(ratio=1)
                
                # Info Content
                info_content = Table.grid(padding=(0, 1))
                info_content.add_column(style="cyan", width=12)
                info_content.add_column(style="white")
                info_content.add_row("👤 User", get_system_username())
                info_content.add_row("🌐 URL", url[:40] + "..." if len(url) > 40 else url)
                info_content.add_row("🔐 Protocol", "[green]HTTPS[/green]" if https_enabled else "[yellow]HTTP[/yellow]")
                info_content.add_row("📁 Directory", directory[:25])
                info_content.add_row("🛡️ Rate Limit", f"5 tries / {BLOCK_DURATION_SECONDS}s ban")
                if token:
                    info_content.add_row("🎫 Token", token)
                
                top_table.add_row(
                    Panel(info_content, title="[bold cyan]📋 Server Info[/bold cyan]", border_style="cyan", box=box.ROUNDED),
                    Panel(log_content if 'log_content' in locals() else "", title="[bold green]📊 Access Log[/bold green]", border_style="green", box=box.ROUNDED)
                )
                
                main_grid.add_row(top_table)
                main_grid.add_row("") # Spacer
                
                # Files Content
                main_grid.add_row(Panel(
                     Align.left(files_text, vertical="top"),
                     title="[bold blue]📁 Hosted Files[/bold blue]",
                     border_style="blue",
                     box=box.ROUNDED,
                     padding=(0, 1),
                     height=12 # Fixed height for stability
                ))

                # Update main layout
                layout["body"].update(main_grid)
                
                # Disable header/footer panels to avoid double borders
                layout["header"].visible = False 
                layout["footer"].update(Align.center(Text("Press Ctrl+C to stop server", style="bold red")))
                
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

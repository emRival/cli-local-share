#!/usr/bin/env python3
"""
FileShare - Simple File Sharing Server with Password Protection
Author: emRival
"""

import http.server
import socketserver
import os
import sys
import socket
import secrets
import threading
import time
import base64
import urllib.parse
from datetime import datetime, timedelta
from functools import partial
from io import BytesIO

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
    import qrcode
except ImportError:
    print("Installing dependencies...")
    os.system("pip3 install --break-system-packages rich qrcode Pillow 2>/dev/null || pip3 install rich qrcode Pillow")
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
    import qrcode

console = Console()

# Global state
ACCESS_LOG = []
SERVER_RUNNING = False
SESSION_TOKEN = None
SESSION_EXPIRY = None


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def generate_qr_text(url: str) -> str:
    """Generate QR code as ASCII text"""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=1,
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # Convert to string
    output = BytesIO()
    qr.print_ascii(out=output, invert=True)
    return output.getvalue().decode('utf-8')


def log_access(ip: str, path: str, status: str):
    """Log access to the server"""
    global ACCESS_LOG
    timestamp = datetime.now().strftime("%H:%M:%S")
    ACCESS_LOG.append({
        "time": timestamp,
        "ip": ip,
        "path": path,
        "status": status
    })
    # Keep only last 20 logs
    if len(ACCESS_LOG) > 20:
        ACCESS_LOG = ACCESS_LOG[-20:]


class AuthHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with Basic Auth"""
    
    def __init__(self, *args, password=None, directory=None, **kwargs):
        self.auth_password = password
        super().__init__(*args, directory=directory, **kwargs)
    
    def log_message(self, format, *args):
        """Override to prevent default logging"""
        pass
    
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="FileShare"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    
    def check_auth(self):
        """Check Basic Auth"""
        if not self.auth_password:
            return True
        
        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            return False
        
        try:
            auth_type, auth_data = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return False
            
            decoded = base64.b64decode(auth_data).decode('utf-8')
            username, password = decoded.split(':', 1)
            return password == self.auth_password
        except:
            return False
    
    def do_GET(self):
        client_ip = self.client_address[0]
        
        if not self.check_auth():
            self.do_AUTHHEAD()
            self.wfile.write(b'Authentication required')
            log_access(client_ip, self.path, "🔒 AUTH FAILED")
            return
        
        log_access(client_ip, self.path, "✅ OK")
        super().do_GET()
    
    def do_HEAD(self):
        if not self.check_auth():
            self.do_AUTHHEAD()
            return
        super().do_HEAD()


def create_server(port: int, directory: str, password: str = None):
    """Create and return HTTP server"""
    handler = partial(AuthHandler, password=password, directory=directory)
    server = socketserver.TCPServer(("", port), handler)
    server.allow_reuse_address = True
    return server


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
║   [bold green]SHARE[/bold green] - Simple File Sharing with Password             ║
║   [dim]Version 1.0.0 | github.com/emRival/scam-check[/dim]          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(banner)


def format_size(size_bytes):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def create_status_display(url: str, directory: str, password: str, timeout: int, qr_text: str):
    """Create status display panel"""
    
    # Server info table
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Key", style="cyan", width=15)
    info_table.add_column("Value", style="white")
    
    info_table.add_row("🌐 URL", f"[bold green]{url}[/bold green]")
    info_table.add_row("📁 Directory", directory)
    info_table.add_row("🔐 Password", password if password else "[dim]None[/dim]")
    info_table.add_row("⏱️  Timeout", f"{timeout} menit" if timeout > 0 else "[dim]No limit[/dim]")
    
    # Files in directory
    files = []
    try:
        for f in os.listdir(directory):
            path = os.path.join(directory, f)
            if os.path.isfile(path):
                size = format_size(os.path.getsize(path))
                files.append(f"📄 {f} ({size})")
            else:
                files.append(f"📁 {f}/")
    except:
        files = ["[dim]Cannot read directory[/dim]"]
    
    files_text = "\n".join(files[:10])
    if len(files) > 10:
        files_text += f"\n[dim]... dan {len(files) - 10} file lainnya[/dim]"
    
    return info_table, files_text, qr_text


def create_log_display():
    """Create access log display"""
    global ACCESS_LOG
    
    if not ACCESS_LOG:
        return "[dim]Belum ada akses...[/dim]"
    
    log_table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
    log_table.add_column("Time", style="dim", width=8)
    log_table.add_column("IP", style="cyan", width=15)
    log_table.add_column("Path", style="white", width=25)
    log_table.add_column("Status", width=15)
    
    for log in ACCESS_LOG[-10:]:
        log_table.add_row(log["time"], log["ip"], log["path"][:25], log["status"])
    
    return log_table


def run_server_with_ui(port: int, directory: str, password: str, timeout: int):
    """Run server with live UI"""
    global SERVER_RUNNING, ACCESS_LOG
    
    ACCESS_LOG = []
    SERVER_RUNNING = True
    
    ip = get_local_ip()
    url = f"http://{ip}:{port}"
    
    # Generate QR code
    qr_text = generate_qr_text(url)
    
    # Create server
    try:
        server = create_server(port, directory, password)
    except OSError as e:
        console.print(f"[red]Error: Port {port} sudah digunakan![/red]")
        return
    
    # Start server in thread
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    start_time = datetime.now()
    end_time = start_time + timedelta(minutes=timeout) if timeout > 0 else None
    
    console.clear()
    
    try:
        with Live(console=console, refresh_per_second=2) as live:
            while SERVER_RUNNING:
                # Check timeout
                if end_time and datetime.now() >= end_time:
                    console.print("\n[yellow]⏱️ Session timeout! Server berhenti.[/yellow]")
                    break
                
                # Calculate remaining time
                if end_time:
                    remaining = end_time - datetime.now()
                    remaining_str = f"{int(remaining.total_seconds() // 60)}m {int(remaining.total_seconds() % 60)}s"
                else:
                    remaining_str = "∞"
                
                # Create layout
                layout = Layout()
                layout.split_column(
                    Layout(name="header", size=3),
                    Layout(name="main"),
                    Layout(name="footer", size=3)
                )
                
                layout["main"].split_row(
                    Layout(name="left", ratio=2),
                    Layout(name="right", ratio=1)
                )
                
                # Header
                header_text = Text()
                header_text.append("📡 FileShare Server Running", style="bold green")
                header_text.append(f"  |  ⏱️ Remaining: {remaining_str}", style="dim")
                layout["header"].update(Panel(header_text, box=box.SIMPLE))
                
                # Info and QR
                info_table, files_text, qr = create_status_display(url, directory, password, timeout, qr_text)
                
                left_content = Table.grid(padding=1)
                left_content.add_row(Panel(info_table, title="📋 Server Info", border_style="cyan"))
                left_content.add_row(Panel(files_text, title="📁 Files", border_style="blue"))
                left_content.add_row(Panel(create_log_display(), title="📊 Access Log", border_style="green"))
                
                layout["left"].update(left_content)
                layout["right"].update(Panel(qr, title="📱 Scan QR", border_style="yellow"))
                
                # Footer
                layout["footer"].update(Panel(
                    "[bold red]Tekan Ctrl+C untuk berhenti[/bold red]",
                    box=box.SIMPLE
                ))
                
                live.update(layout)
                time.sleep(0.5)
                
    except KeyboardInterrupt:
        pass
    finally:
        SERVER_RUNNING = False
        server.shutdown()
        console.print("\n[cyan]👋 Server berhenti. Terima kasih![/cyan]\n")


def main():
    """Main entry point"""
    console.clear()
    print_banner()
    
    console.print("\n[bold cyan]📁 FILE SHARE SETUP[/bold cyan]\n")
    
    # Get directory
    default_dir = os.getcwd()
    directory = console.input(f"[yellow]Directory to share[/yellow] [{default_dir}]: ").strip()
    if not directory:
        directory = default_dir
    
    if not os.path.isdir(directory):
        console.print(f"[red]Error: Directory '{directory}' tidak ditemukan![/red]")
        return
    
    # Get port
    port_str = console.input("[yellow]Port[/yellow] [8080]: ").strip()
    port = int(port_str) if port_str else 8080
    
    # Get password
    password = console.input("[yellow]Password[/yellow] (kosongkan jika tidak perlu): ").strip()
    if not password:
        password = None
    
    # Get timeout
    timeout_str = console.input("[yellow]Session timeout (menit)[/yellow] [30]: ").strip()
    timeout = int(timeout_str) if timeout_str else 30
    
    console.print("\n[green]✓ Starting server...[/green]\n")
    time.sleep(1)
    
    run_server_with_ui(port, directory, password, timeout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[cyan]👋 Bye![/cyan]")

#!/usr/bin/env python3
"""
FileShare v2.0 - Secure File Sharing Server
Author: emRival

Security Features:
- HTTPS (self-signed certificate)
- Password + Access Token authentication
- Rate limiting (block after failed attempts)
- IP Whitelist with network scanning
"""

import http.server
import socketserver
import ssl
import os
import sys
import socket
import secrets
import threading
import time
import base64
import subprocess
import ipaddress
from datetime import datetime, timedelta
from functools import partial
from io import BytesIO
from collections import defaultdict
from typing import Set, Dict, List, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
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
    from rich.prompt import Prompt, Confirm
    from rich import box
    import qrcode

console = Console()

# Global state
ACCESS_LOG: List[Dict] = []
SERVER_RUNNING = False
BLOCKED_IPS: Dict[str, datetime] = {}
FAILED_ATTEMPTS: Dict[str, int] = defaultdict(int)
WHITELIST_IPS: Set[str] = set()

# Security settings
MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15


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


def scan_network() -> List[Dict[str, str]]:
    """Scan network for active hosts"""
    console.print("[yellow]🔍 Scanning network... (this may take a moment)[/yellow]")
    
    network_range = get_network_range()
    local_ip = get_local_ip()
    active_hosts = []
    
    try:
        network = ipaddress.IPv4Network(network_range, strict=False)
        
        def ping_host(ip: str) -> Optional[Dict[str, str]]:
            try:
                # Quick ping with 1 second timeout
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", str(ip)],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(str(ip))[0]
                    except:
                        hostname = "Unknown"
                    return {"ip": str(ip), "hostname": hostname}
            except:
                pass
            return None
        
        # Scan in parallel using threads
        threads = []
        results = []
        
        for ip in list(network.hosts())[:254]:  # Limit to 254 hosts
            if str(ip) == local_ip:
                active_hosts.append({"ip": str(ip), "hostname": "This Server"})
                continue
            
            t = threading.Thread(target=lambda ip=ip: results.append(ping_host(str(ip))))
            threads.append(t)
            t.start()
        
        # Wait for all threads with timeout
        for t in threads:
            t.join(timeout=0.1)
        
        # Collect results
        for r in results:
            if r:
                active_hosts.append(r)
                
    except Exception as e:
        console.print(f"[red]Error scanning: {e}[/red]")
    
    return active_hosts


def generate_access_token() -> str:
    """Generate random access token"""
    return secrets.token_urlsafe(16)


def generate_self_signed_cert(cert_file: str, key_file: str):
    """Generate self-signed SSL certificate"""
    try:
        # Check if openssl is available
        result = subprocess.run(
            ["openssl", "version"],
            capture_output=True
        )
        if result.returncode != 0:
            return False
        
        # Generate certificate
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_file, "-out", cert_file,
            "-days", "365", "-nodes",
            "-subj", "/CN=FileShare/O=FileShare/C=ID"
        ], capture_output=True)
        
        return os.path.exists(cert_file) and os.path.exists(key_file)
    except:
        return False


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
    if len(ACCESS_LOG) > 30:
        ACCESS_LOG = ACCESS_LOG[-30:]


def is_ip_blocked(ip: str) -> bool:
    """Check if IP is blocked"""
    if ip in BLOCKED_IPS:
        if datetime.now() < BLOCKED_IPS[ip]:
            return True
        else:
            # Unblock after duration
            del BLOCKED_IPS[ip]
            FAILED_ATTEMPTS[ip] = 0
    return False


def record_failed_attempt(ip: str):
    """Record failed login attempt"""
    global FAILED_ATTEMPTS, BLOCKED_IPS
    FAILED_ATTEMPTS[ip] += 1
    
    if FAILED_ATTEMPTS[ip] >= MAX_FAILED_ATTEMPTS:
        BLOCKED_IPS[ip] = datetime.now() + timedelta(minutes=BLOCK_DURATION_MINUTES)
        log_access(ip, "-", f"🚫 BLOCKED ({BLOCK_DURATION_MINUTES}min)")


def is_ip_whitelisted(ip: str) -> bool:
    """Check if IP is in whitelist (empty whitelist = allow all)"""
    if not WHITELIST_IPS:
        return True
    return ip in WHITELIST_IPS or ip == "127.0.0.1"


class SecureAuthHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with enhanced security"""
    
    def __init__(self, *args, password=None, token=None, directory=None, **kwargs):
        self.auth_password = password
        self.auth_token = token
        super().__init__(*args, directory=directory, **kwargs)
    
    def log_message(self, format, *args):
        pass
    
    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="FileShare Secure"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    
    def send_blocked_response(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>403 Forbidden</h1><p>Your IP has been blocked due to too many failed attempts.</p>')
    
    def send_whitelist_denied(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>403 Forbidden</h1><p>Your IP is not in the whitelist.</p>')
    
    def check_auth(self) -> bool:
        """Check authentication"""
        if not self.auth_password and not self.auth_token:
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
            
            # Check password
            if self.auth_password and password == self.auth_password:
                return True
            
            # Check token (username can be 'token' and password is the token)
            if self.auth_token and password == self.auth_token:
                return True
            
            # Check combined (password:token format)
            if self.auth_password and self.auth_token:
                if password == f"{self.auth_password}:{self.auth_token}":
                    return True
            
            return False
        except:
            return False
    
    def do_GET(self):
        client_ip = self.client_address[0]
        
        # Check if IP is blocked
        if is_ip_blocked(client_ip):
            self.send_blocked_response()
            log_access(client_ip, self.path, "🚫 BLOCKED")
            return
        
        # Check whitelist
        if not is_ip_whitelisted(client_ip):
            self.send_whitelist_denied()
            log_access(client_ip, self.path, "⛔ NOT WHITELISTED")
            return
        
        # Check auth
        if not self.check_auth():
            self.do_AUTHHEAD()
            self.wfile.write(b'Authentication required. Use password or token.')
            record_failed_attempt(client_ip)
            log_access(client_ip, self.path, "🔒 AUTH FAILED")
            return
        
        # Reset failed attempts on success
        FAILED_ATTEMPTS[client_ip] = 0
        log_access(client_ip, self.path, "✅ OK")
        super().do_GET()
    
    def do_HEAD(self):
        client_ip = self.client_address[0]
        if is_ip_blocked(client_ip) or not is_ip_whitelisted(client_ip):
            return
        if not self.check_auth():
            self.do_AUTHHEAD()
            return
        super().do_HEAD()


def create_server(port: int, directory: str, password: str = None, token: str = None, use_https: bool = False):
    """Create HTTP/HTTPS server"""
    handler = partial(SecureAuthHandler, password=password, token=token, directory=directory)
    server = socketserver.TCPServer(("", port), handler)
    server.allow_reuse_address = True
    
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


def format_size(size_bytes):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def create_status_display(url: str, directory: str, password: str, token: str, 
                          timeout: int, use_https: bool, qr_text: str):
    """Create status display"""
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Key", style="cyan", width=15)
    info_table.add_column("Value", style="white")
    
    protocol = "[bold green]🔒 HTTPS[/bold green]" if use_https else "[yellow]⚠️ HTTP[/yellow]"
    info_table.add_row("🌐 URL", f"[bold]{url}[/bold]")
    info_table.add_row("🔐 Protocol", protocol)
    info_table.add_row("📁 Directory", directory[:30])
    info_table.add_row("� Password", password if password else "[dim]None[/dim]")
    info_table.add_row("🎫 Token", token[:20] + "..." if token else "[dim]None[/dim]")
    info_table.add_row("⏱️  Timeout", f"{timeout}m" if timeout > 0 else "∞")
    info_table.add_row("📋 Whitelist", f"{len(WHITELIST_IPS)} IPs" if WHITELIST_IPS else "[dim]All allowed[/dim]")
    info_table.add_row("🚫 Blocked", f"{len(BLOCKED_IPS)} IPs" if BLOCKED_IPS else "[dim]None[/dim]")
    
    # Files
    files = []
    try:
        for f in os.listdir(directory)[:8]:
            path = os.path.join(directory, f)
            if os.path.isfile(path):
                size = format_size(os.path.getsize(path))
                files.append(f"📄 {f[:20]} ({size})")
            else:
                files.append(f"📁 {f[:20]}/")
    except:
        files = ["[dim]Cannot read[/dim]"]
    
    files_text = "\n".join(files)
    
    return info_table, files_text, qr_text


def create_log_display():
    """Create access log display"""
    if not ACCESS_LOG:
        return "[dim]No access yet...[/dim]"
    
    log_table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
    log_table.add_column("Time", style="dim", width=8)
    log_table.add_column("IP", style="cyan", width=15)
    log_table.add_column("Status", width=20)
    
    for log in ACCESS_LOG[-8:]:
        log_table.add_row(log["time"], log["ip"], log["status"])
    
    return log_table


def setup_whitelist():
    """Interactive whitelist setup"""
    global WHITELIST_IPS
    
    console.print("\n[bold cyan]🛡️ IP WHITELIST SETUP[/bold cyan]\n")
    
    use_whitelist = Confirm.ask("Aktifkan IP Whitelist?", default=False)
    
    if not use_whitelist:
        WHITELIST_IPS = set()
        return
    
    console.print("\n[yellow]Pilih metode:[/yellow]")
    console.print("1. Manual - Masukkan IP satu per satu")
    console.print("2. Scan - Scan jaringan dan pilih IP")
    console.print("3. Both - Manual + Scan")
    
    method = Prompt.ask("Pilihan", choices=["1", "2", "3"], default="2")
    
    if method in ["1", "3"]:
        console.print("\n[yellow]Masukkan IP (pisahkan dengan koma, atau 'done' untuk selesai):[/yellow]")
        while True:
            ip_input = input("> ").strip()
            if ip_input.lower() == 'done' or not ip_input:
                break
            
            for ip in ip_input.split(','):
                ip = ip.strip()
                try:
                    ipaddress.IPv4Address(ip)
                    WHITELIST_IPS.add(ip)
                    console.print(f"[green]✓ Added: {ip}[/green]")
                except:
                    console.print(f"[red]✗ Invalid IP: {ip}[/red]")
    
    if method in ["2", "3"]:
        hosts = scan_network()
        
        if hosts:
            console.print(f"\n[green]Found {len(hosts)} hosts:[/green]\n")
            
            for i, host in enumerate(hosts, 1):
                status = "[green]✓[/green]" if host["ip"] in WHITELIST_IPS else "[ ]"
                console.print(f"{status} {i}. {host['ip']} ({host['hostname']})")
            
            console.print("\n[yellow]Masukkan nomor yang ingin di-whitelist (pisahkan dengan koma):[/yellow]")
            console.print("[dim]Contoh: 1,3,5 atau 'all' untuk semua atau 'none' untuk skip[/dim]")
            
            selection = input("> ").strip().lower()
            
            if selection == 'all':
                for host in hosts:
                    WHITELIST_IPS.add(host["ip"])
            elif selection != 'none' and selection:
                try:
                    indices = [int(x.strip()) - 1 for x in selection.split(',')]
                    for idx in indices:
                        if 0 <= idx < len(hosts):
                            WHITELIST_IPS.add(hosts[idx]["ip"])
                except:
                    console.print("[red]Invalid selection[/red]")
    
    # Always add localhost
    WHITELIST_IPS.add("127.0.0.1")
    
    console.print(f"\n[green]✓ Whitelist configured with {len(WHITELIST_IPS)} IPs[/green]")
    for ip in sorted(WHITELIST_IPS):
        console.print(f"  • {ip}")


def run_server_with_ui(port: int, directory: str, password: str, token: str, 
                        timeout: int, use_https: bool):
    """Run server with live UI"""
    global SERVER_RUNNING, ACCESS_LOG, BLOCKED_IPS, FAILED_ATTEMPTS
    
    ACCESS_LOG = []
    BLOCKED_IPS = {}
    FAILED_ATTEMPTS = defaultdict(int)
    SERVER_RUNNING = True
    
    ip = get_local_ip()
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{ip}:{port}"
    
    qr_text = generate_qr_text(url)
    
    try:
        server, https_enabled = create_server(port, directory, password, token, use_https)
        if use_https and not https_enabled:
            url = f"http://{ip}:{port}"
            qr_text = generate_qr_text(url)
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
        with Live(console=console, refresh_per_second=2) as live:
            while SERVER_RUNNING:
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
                
                layout["main"].split_row(
                    Layout(name="left", ratio=2),
                    Layout(name="right", ratio=1)
                )
                
                header_text = Text()
                header_text.append("📡 FileShare Server Running", style="bold green")
                header_text.append(f"  |  ⏱️ {remaining_str}", style="dim")
                header_text.append(f"  |  🛡️ {len(WHITELIST_IPS)} whitelisted", style="dim")
                layout["header"].update(Panel(header_text, box=box.SIMPLE))
                
                info_table, files_text, qr = create_status_display(
                    url, directory, password, token, timeout, https_enabled, qr_text
                )
                
                left_content = Table.grid(padding=1)
                left_content.add_row(Panel(info_table, title="📋 Info", border_style="cyan"))
                left_content.add_row(Panel(files_text, title="📁 Files", border_style="blue"))
                left_content.add_row(Panel(create_log_display(), title="📊 Log", border_style="green"))
                
                layout["left"].update(left_content)
                layout["right"].update(Panel(qr, title="📱 QR", border_style="yellow"))
                
                layout["footer"].update(Panel(
                    "[bold red]Ctrl+C to stop[/bold red]",
                    box=box.SIMPLE
                ))
                
                live.update(layout)
                time.sleep(0.5)
                
    except KeyboardInterrupt:
        pass
    finally:
        SERVER_RUNNING = False
        server.shutdown()
        console.print("\n[cyan]👋 Server stopped.[/cyan]\n")


def main():
    """Main entry point"""
    console.clear()
    print_banner()
    
    console.print("\n[bold cyan]📁 FILE SHARE SETUP[/bold cyan]\n")
    
    # Directory
    default_dir = os.getcwd()
    console.print(f"[yellow]Directory to share[/yellow] [default: {default_dir}]")
    directory = input("> ").strip() or default_dir
    
    if not os.path.isdir(directory):
        console.print("[red]Error: Directory not found![/red]")
        return
    
    # Port
    port = int(Prompt.ask("[yellow]Port[/yellow]", default="8080"))
    
    # HTTPS
    use_https = Confirm.ask("[yellow]Enable HTTPS?[/yellow]", default=True)
    
    # Password
    password = Prompt.ask("[yellow]Password[/yellow]", default="", password=True)
    password = password if password else None
    
    # Token
    use_token = Confirm.ask("[yellow]Generate access token?[/yellow]", default=True)
    token = generate_access_token() if use_token else None
    
    if token:
        console.print(f"\n[green]🎫 Access Token: [bold]{token}[/bold][/green]")
        console.print("[dim]Use this token as password, or combine: password:token[/dim]\n")
    
    # Timeout
    timeout = int(Prompt.ask("[yellow]Session timeout (minutes, 0=unlimited)[/yellow]", default="30"))
    
    # Whitelist
    setup_whitelist()
    
    console.print("\n[green]✓ Starting server...[/green]\n")
    time.sleep(1)
    
    run_server_with_ui(port, directory, password, token, timeout, use_https)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[cyan]👋 Bye![/cyan]")

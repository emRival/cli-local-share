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
    from rich.align import Align
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
    from rich.align import Align
    import qrcode
    
    import qrcode

# Try importing config, handle if missing
try:
    from src.config import load_config, save_config
except ImportError:
    def load_config(): return {}
    def save_config(c): pass

console = Console()

# Global state
ACCESS_LOG: List[Dict] = []
SERVER_RUNNING = False
BLOCKED_IPS: Dict[str, datetime] = {}
FAILED_ATTEMPTS: Dict[str, int] = defaultdict(int)
WHITELIST_IPS: Set[str] = set()

# Security settings
MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION_SECONDS = 300  # 5 minutes
SYSTEM_USERNAME = ""


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


def is_port_in_use(port: int) -> bool:
    """Check if port is already in use"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0


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
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(url)
        qr.make(fit=True)
        
        # Use StringIO for text output (Python 3.13 compatibility)
        from io import StringIO
        output = StringIO()
        # Use basic ASCII characters for better compatibility and alignment
        qr.print_ascii(out=output, invert=True)
        return output.getvalue()
    except Exception as e:
        return f"[QR Code for: {url}]"


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
        BLOCKED_IPS[ip] = datetime.now() + timedelta(seconds=BLOCK_DURATION_SECONDS)
        log_access(ip, "-", f"🚫 BLOCKED ({BLOCK_DURATION_SECONDS}s)")


def is_ip_whitelisted(ip: str) -> bool:
    """Check if IP is in whitelist (empty whitelist = allow all)"""
    if not WHITELIST_IPS:
        return True
    return ip in WHITELIST_IPS or ip == "127.0.0.1"


class SecureAuthHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with enhanced security and download UI"""
    
    def __init__(self, *args, password=None, token=None, directory=None, **kwargs):
        self.auth_password = password
        self.auth_token = token
        self.share_directory = directory
        super().__init__(*args, directory=directory, **kwargs)
    
    def log_message(self, format, *args):
        pass
    
    def do_AUTHHEAD(self):
        self.send_response(401)
        realm = f'FileShare - User: {get_system_username()}'
        self.send_header('WWW-Authenticate', f'Basic realm="{realm}"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    
    def get_upload_path(self, filename: str) -> Optional[str]:
        """Securely resolve upload path"""
        import os
        
        # Simple secure filename implementation (no external deps)
        def secure_filename(name):
            # Keep only safe characters
            return "".join([c for c in name if c.isalpha() or c.isdigit() or c in '._-'])
            
        clean_name = secure_filename(os.path.basename(filename))
        if not clean_name:
            return None
            
        # Target directory is the current view directory
        # Parse output directory from referer or path
        # Simple approach: upload to the current directory being viewed
        # But do_POST path usually matches the form action. 
        # We will assume POST to current directory.
        
        target_dir = self.translate_path(self.path)
        if not os.path.isdir(target_dir):
            return None
            
        full_path = os.path.join(target_dir, clean_name)
        
        # Anti-overwrite: Append number if exists
        base, ext = os.path.splitext(full_path)
        counter = 1
        while os.path.exists(full_path):
            full_path = f"{base}_{counter}{ext}"
            counter += 1
            
        return full_path

    def do_POST(self):
        """Handle file uploads"""
        client_ip = self.client_address[0]
        
        # Security checks
        if is_ip_blocked(client_ip):
            self.send_blocked_response()
            return
            
        if not is_ip_whitelisted(client_ip):
            self.send_whitelist_denied()
            return
            
        if not self.check_auth():
            self.do_AUTHHEAD()
            return
            
        # Check content type
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            self.send_error(400, "Bad Request: Must be multipart/form-data")
            return
            
        try:
            # Parse multipart data using email library (Python 3 native)
            import email, email.policy
            length = int(self.headers.get('content-length'))
            body = self.rfile.read(length)
            
            # Create a message object
            headers = f"Content-Type: {content_type}\n"
            msg = email.message_from_bytes(headers.encode() + b"\n" + body, policy=email.policy.default)
            
            uploaded_files = []
            
            for part in msg.iter_parts():
                filename = part.get_filename()
                if filename:
                    # It's a file
                    upload_path = self.get_upload_path(filename)
                    if upload_path:
                        content = part.get_payload(decode=True)
                        if content:
                            with open(upload_path, 'wb') as f:
                                f.write(content)
                            uploaded_files.append(os.path.basename(upload_path))
            
            # Redirect back to the page
            self.send_response(303)
            self.send_header('Location', self.path)
            self.end_headers()
            
            if uploaded_files:
                log_access(client_ip, f"⬆️ Uploaded: {', '.join(uploaded_files)}", "✅ OK")
            else:
                log_access(client_ip, "Upload attempt (no file)", "⚠️ FAIL")
                
        except Exception as e:
            self.send_error(500, f"Upload failed: {str(e)}")
            log_access(client_ip, "Upload error", "❌ ERR")
    
    def send_blocked_response(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>403 Forbidden</h1><p>Your IP has been blocked.</p>')
    
    def send_whitelist_denied(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>403 Forbidden</h1><p>Your IP is not whitelisted.</p>')
    
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
            
            # Check password or token
            if self.auth_password and password == self.auth_password:
                return True
            if self.auth_token and password == self.auth_token:
                return True
            
            return False
        except:
            return False
    
    def generate_html_page(self, path: str) -> bytes:
        """Generate custom HTML page with download buttons, upload, and search"""
        import urllib.parse
        
        full_path = self.translate_path(path)
        
        if not os.path.isdir(full_path):
            return None
        
        items = []
        try:
            entries = os.listdir(full_path)
        except OSError:
            entries = []
        
        # Add parent directory link if not root
        if path != '/':
            items.append({
                'name': '📁 ..',
                'href': urllib.parse.quote(os.path.dirname(path.rstrip('/')) or '/'),
                'size': '',
                'is_dir': True,
                'download': '',
                'preview': False
            })
        
        for name in sorted(entries):
            if name.startswith('.'):
                continue
            item_path = os.path.join(full_path, name)
            href = urllib.parse.quote(os.path.join(path, name))
            
            # Simple preview support
            ext = os.path.splitext(name)[1].lower()
            can_preview = ext in ['.png', '.jpg', '.jpeg', '.gif', '.txt', '.md', '.py', '.log', '.json', '.css', '.html', '.js']
            
            if os.path.isdir(item_path):
                try:
                    count = len(os.listdir(item_path))
                    size = f"{count} items"
                except:
                    size = ""
                items.append({
                    'name': f'📁 {name}',
                    'href': href + '/',
                    'size': size,
                    'is_dir': True,
                    'download': f'?download_zip={urllib.parse.quote(name)}',
                    'preview': False
                })
            else:
                size = format_size(os.path.getsize(item_path))
                items.append({
                    'name': f'📄 {name}',
                    'href': href,
                    'is_dir': False,
                    'size': size,
                    'download': href,
                    'preview': can_preview
                })
        
        # Generate HTML Rows
        rows = ""
        for item in items:
            if item['is_dir'] and item['name'] != '📁 ..':
                actions = f'<a href="{item["download"]}" class="btn btn-zip">📦 ZIP</a>'
            elif not item['is_dir']:
                actions = f'<a href="{item["download"]}" download class="btn btn-dl">⬇️ DL</a>'
                if item['preview']:
                    actions += f' <button onclick="previewFile(\'{item["href"]}\', \'{item["name"]}\')" class="btn btn-view">👁️ View</button>'
            else:
                actions = ''
            
            rows += f'''
            <tr>
                <td><a href="{item['href']}">{item['name']}</a></td>
                <td>{item['size']}</td>
                <td class="actions">{actions}</td>
            </tr>
            '''
        
        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>FileShare - {path}</title>
    <style>
        :root {{ --primary: #00d9ff; --bg: #1a1a2e; --surface: rgba(255,255,255,0.05); }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        
        /* Header & Search */
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }}
        h1 {{ color: var(--primary); font-size: 1.5rem; }}
        .path {{ color: #888; margin-bottom: 20px; word-break: break-all; background: rgba(0,0,0,0.2); padding: 10px; border-radius: 5px; }}
        
        .search-box {{
            padding: 8px 15px;
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.2);
            background: rgba(0,0,0,0.2);
            color: white;
            width: 100%;
            max-width: 300px;
        }}
        
        /* Upload Zone */
        .upload-zone {{
            border: 2px dashed rgba(255,255,255,0.2);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
            transition: all 0.3s;
            cursor: pointer;
        }}
        .upload-zone:hover, .upload-zone.dragover {{ border-color: var(--primary); background: rgba(0,217,255,0.1); }}
        .upload-btn {{ display: none; }}
        .upload-label {{ color: #aaa; cursor: pointer; display: block; }}
        
        /* Table */
        .table-container {{ overflow-x: auto; background: var(--surface); border-radius: 10px; }}
        table {{ width: 100%; border-collapse: collapse; min-width: 600px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        th {{ background: rgba(0,217,255,0.1); color: var(--primary); position: sticky; top: 0; }}
        tr:hover {{ background: rgba(255,255,255,0.05); }}
        a {{ color: var(--primary); text-decoration: none; }}
        
        /* Buttons */
        .btn {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.8rem; border: none; cursor: pointer; margin-right: 5px; text-decoration: none !important; color: #000 !important; font-weight: bold; }}
        .btn-dl {{ background: var(--primary); }}
        .btn-zip {{ background: #ff9800; }}
        .btn-view {{ background: #4caf50; color: white !important; }}
        .btn:hover {{ opacity: 0.9; transform: translateY(-1px); }}
        
        /* Preview Modal */
        .modal {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 1000; justify-content: center; align-items: center; }}
        .modal-content {{ max-width: 90%; max-height: 90%; background: #222; padding: 20px; border-radius: 10px; position: relative; display: flex; flex-direction: column; }}
        .modal-close {{ position: absolute; top: 10px; right: 15px; color: white; font-size: 24px; cursor: pointer; }}
        .preview-frame {{ width: 80vw; height: 80vh; border: none; background: white; }}
        .preview-img {{ max-width: 100%; max-height: 80vh; object-fit: contain; }}
        
        .footer {{ margin-top: 30px; text-align: center; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📁 FileShare</h1>
            <input type="text" id="searchInput" class="search-box" placeholder="🔍 Search files..." onkeyup="filterFiles()">
        </div>
        
        <p class="path">{path}</p>
        
        <form action="{path}" method="post" enctype="multipart/form-data" id="uploadForm">
            <div class="upload-zone" id="dropZone">
                <label for="fileInput" class="upload-label">
                    ☁️ <strong>Drag & Drop files here</strong> or click to upload
                </label>
                <input type="file" name="files" id="fileInput" class="upload-btn" multiple onchange="document.getElementById('uploadForm').submit()">
            </div>
        </form>

        <div class="table-container">
            <table id="fileTable">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        
        <p class="footer">🔒 FileShare v2.5 | {get_system_username()}@{get_local_ip()}</p>
    </div>

    <!-- Preview Modal -->
    <div id="previewModal" class="modal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h3 id="previewTitle" style="color:white; margin-bottom:10px;"></h3>
            <div id="previewContainer"></div>
        </div>
    </div>

    <script>
        // Search Filter
        function filterFiles() {{
            let input = document.getElementById('searchInput');
            let filter = input.value.toLowerCase();
            let table = document.getElementById('fileTable');
            let tr = table.getElementsByTagName('tr');

            for (let i = 1; i < tr.length; i++) {{
                let td = tr[i].getElementsByTagName('td')[0];
                if (td) {{
                    let txtValue = td.textContent || td.innerText;
                    if (txtValue.toLowerCase().indexOf(filter) > -1) {{
                        tr[i].style.display = "";
                    }} else {{
                        tr[i].style.display = "none";
                    }}
                }}
            }}
        }}

        // Drag & Drop
        let dropZone = document.getElementById('dropZone');
        
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {{
            dropZone.addEventListener(eventName, preventDefaults, false);
        }});

        function preventDefaults(e) {{
            e.preventDefault();
            e.stopPropagation();
        }}

        ['dragenter', 'dragover'].forEach(eventName => {{
            dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
        }});

        ['dragleave', 'drop'].forEach(eventName => {{
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
        }});

        dropZone.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {{
            let dt = e.dataTransfer;
            let files = dt.files;
            document.getElementById('fileInput').files = files;
            document.getElementById('uploadForm').submit();
        }}

        // Preview Logic
        function previewFile(url, name) {{
            let modal = document.getElementById('previewModal');
            let container = document.getElementById('previewContainer');
            let title = document.getElementById('previewTitle');
            
            title.innerText = name;
            container.innerHTML = 'Loading...';
            modal.style.display = 'flex';
            
            let ext = name.split('.').pop().toLowerCase();
            
            if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp'].includes(ext)) {{
                container.innerHTML = `<img src="${{url}}" class="preview-img">`;
            }} else {{
                container.innerHTML = `<iframe src="${{url}}" class="preview-frame"></iframe>`;
            }}
        }}

        function closeModal(e) {{
            if (!e || e.target === document.getElementById('previewModal') || e.target.classList.contains('modal-close')) {{
                document.getElementById('previewModal').style.display = 'none';
                document.getElementById('previewContainer').innerHTML = '';
            }}
        }}
        
        document.onkeydown = function(evt) {{
            evt = evt || window.event;
            if (evt.keyCode == 27) {{
                closeModal();
            }}
        }};
    </script>
</body>
</html>'''
        return html.encode('utf-8')
    
    def create_zip_folder(self, folder_name: str) -> Optional[bytes]:
        """Create zip of a folder and return bytes"""
        import zipfile
        import io
        
        folder_path = os.path.join(self.translate_path('/'), folder_name)
        if not os.path.isdir(folder_path):
            return None
        
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    try:
                        zf.write(file_path, os.path.join(folder_name, arcname))
                    except:
                        pass
        
        return buffer.getvalue()
    
    def do_GET(self):
        client_ip = self.client_address[0]
        
        # Security checks
        if is_ip_blocked(client_ip):
            self.send_blocked_response()
            log_access(client_ip, self.path, "🚫 BLOCKED")
            return
        
        if not is_ip_whitelisted(client_ip):
            self.send_whitelist_denied()
            log_access(client_ip, self.path, "⛔ NOT WHITELISTED")
            return
        
        if not self.check_auth():
            self.do_AUTHHEAD()
            self.wfile.write(f'Login - Username: {get_system_username()}'.encode())
            record_failed_attempt(client_ip)
            log_access(client_ip, self.path, "🔒 AUTH FAILED")
            return
        
        FAILED_ATTEMPTS[client_ip] = 0
        
        # Handle zip download
        if '?download_zip=' in self.path:
            import urllib.parse
            query = self.path.split('?download_zip=')[1]
            folder_name = urllib.parse.unquote(query)
            zip_data = self.create_zip_folder(folder_name)
            
            if zip_data:
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', f'attachment; filename="{folder_name}.zip"')
                self.send_header('Content-Length', len(zip_data))
                self.end_headers()
                self.wfile.write(zip_data)
                log_access(client_ip, f"📦 {folder_name}.zip", "✅ ZIP")
                return
        
        # Check if directory - serve custom HTML
        path = self.path.split('?')[0]  # Remove query string
        full_path = self.translate_path(path)
        
        if os.path.isdir(full_path):
            html = self.generate_html_page(path)
            if html:
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', len(html))
                self.end_headers()
                self.wfile.write(html)
                log_access(client_ip, path, "✅ OK")
                return
        
        # Serve file normally
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
    # Use explicit width for stability
    info_table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    info_table.add_column("Key", style="cyan", width=12)
    info_table.add_column("Value", style="white")
    
    protocol = "[bold green]🔒 HTTPS[/bold green]" if use_https else "[yellow]⚠️ HTTP[/yellow]"
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
    
    return info_table, files_text, qr_text


def create_log_display():
    """Create access log display"""
    if not ACCESS_LOG:
        return "[dim]No access yet...[/dim]"
    
    log_table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1), expand=True)
    log_table.add_column("Time", style="dim", width=10)
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
        # Hide cursor for cleaner display
        console.show_cursor(False)
        with Live(console=console, refresh_per_second=4, screen=True) as live:
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
                layout["header"].update(Panel(header_text, box=box.ROUNDED))
                
                info_table, files_text, qr = create_status_display(
                    url, directory, password, token, timeout, https_enabled, qr_text
                )
                
                left_content = Table.grid(padding=1, expand=True)
                left_content.add_column(ratio=1)
                left_content.add_row(Panel(info_table, title="📋 Info", border_style="cyan", box=box.ROUNDED))
                left_content.add_row(Panel(files_text, title="📁 Files", border_style="blue", box=box.ROUNDED))
                left_content.add_row(Panel(create_log_display(), title="📊 Log", border_style="green", box=box.ROUNDED))
                
                layout["left"].update(left_content)
                
                # Center QR code vertically and horizontally
                qr_panel = Panel(
                    Align.center(qr, vertical="middle"), 
                    title="📱 QR Code", 
                    border_style="yellow", 
                    box=box.ROUNDED,
                    padding=(1, 1)
                )
                layout["right"].update(qr_panel)
                
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
        SERVER_RUNNING = False
        try:
            server.shutdown()
            server.server_close()  # Release port immediately
        except:
            pass
        console.print("\n[cyan]👋 Server stopped.[/cyan]\n")


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
            # Add parent directory option
            items.append({"name": "..", "type": "dir", "size": ""})
            
            for name in sorted(os.listdir(current_dir)):
                path = os.path.join(current_dir, name)
                if os.path.isdir(path):
                    items.append({"name": name, "type": "dir", "size": ""})
                else:
                    size = format_size(os.path.getsize(path))
                    items.append({"name": name, "type": "file", "size": size})
        except PermissionError:
            console.print("[red]❌ Permission denied![/red]")
            current_dir = os.path.dirname(current_dir)
            time.sleep(1)
            continue
        
        # Display items
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("#", style="dim", width=4)
        table.add_column("Name", style="white")
        table.add_column("Type", style="cyan", width=8)
        table.add_column("Size", style="dim", width=10)
        
        for i, item in enumerate(items):
            icon = "📁" if item["type"] == "dir" else "📄"
            table.add_row(
                str(i),
                f"{icon} {item['name']}",
                item["type"],
                item["size"]
            )
        
        console.print(table)
        
        console.print("\n[yellow]Commands:[/yellow]")
        console.print("  [cyan]<number>[/cyan] - Enter directory / select")
        console.print("  [cyan]s[/cyan]       - Select current directory")
        console.print("  [cyan]p <path>[/cyan] - Go to path directly")
        console.print("  [cyan]h[/cyan]       - Go to home directory")
        console.print("  [cyan]q[/cyan]       - Cancel\n")
        
        console.print("  [cyan]h[/cyan]       - Go to home directory")
        console.print("  [cyan]q[/cyan]       - Cancel\n")
        
        try:
            choice_input = Prompt.ask("> ")
            # Strip ANSI codes if any
            import re
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            choice = ansi_escape.sub('', choice_input).strip().lower()
        except:
            choice = ""
        
        if choice == 'q':
            return os.getcwd()
        elif choice == 's':
            return current_dir
        elif choice == 'h':
            current_dir = os.path.expanduser("~")
        elif choice.startswith('p '):
            new_path = choice[2:].strip()
            if os.path.isdir(new_path):
                current_dir = os.path.abspath(new_path)
            else:
                console.print(f"[red]Path not found: {new_path}[/red]")
                time.sleep(1)
        elif choice.isdigit():
            idx = int(choice)
            if 0 <= idx < len(items):
                selected = items[idx]
                if selected["type"] == "dir":
                    if selected["name"] == "..":
                        current_dir = os.path.dirname(current_dir)
                    else:
                        current_dir = os.path.join(current_dir, selected["name"])
                else:
                    # If file selected, use its parent directory
                    console.print(f"[yellow]Selected directory: {current_dir}[/yellow]")
                    if Confirm.ask("Use this directory?", default=True):
                        return current_dir


def ask_robust_int(prompt_text: str, default: str) -> int:
    """Robust integer input with ANSI code stripping"""
    while True:
        try:
            val_input = Prompt.ask(prompt_text, default=default)
            # Strip ANSI codes and non-digits
            val_clean = ''.join(filter(str.isdigit, val_input))
            
            if not val_clean:
                console.print("[red]❌ Invalid input! Please enter a number.[/red]")
                continue
                
            return int(val_clean)
        except ValueError:
            console.print("[red]❌ Invalid input! Please enter a valid number.[/red]")


def main():

    """Main entry point"""
    console.clear()
    print_banner()
    
    # Load config
    config = load_config()
    default_dir = config.get("last_directory", os.getcwd())
    if not os.path.isdir(default_dir):
        default_dir = os.getcwd()

    console.print("\n[bold cyan]📁 FILE SHARE SETUP[/bold cyan]\n")
    
    # Directory selection
    console.print("[yellow]Select directory to share:[/yellow]")
    console.print("  [cyan]1[/cyan] - Browse (interactive file browser)")
    console.print("  [cyan]2[/cyan] - Type path manually")
    console.print("  [cyan]3[/cyan] - Use current directory")
    console.print(f"      [dim](Last used: {default_dir})[/dim]")
    console.print("  [cyan]u[/cyan] - Check for updates\n")
    
    # Intelligent default: use 3 if last used is set, else 1
    dir_choice_default = "3" if config.get("last_directory") else "1"
    dir_choice = Prompt.ask("Choice", choices=["1", "2", "3", "u"], default=dir_choice_default)
    
    directory = default_dir # Default fallback
    
    if dir_choice == "u":
        update_tool()
        # After update check (if no update), restart main
        main()
        return
    elif dir_choice == "1":
        directory = browse_directory()
    elif dir_choice == "2":
        directory = input(f"Path (default: {default_dir})> ").strip()
        if not directory:
            directory = default_dir
    else:
        directory = default_dir
    
    if not os.path.isdir(directory):
        console.print("[red]Error: Directory not found![/red]")
        return
    
    # Clear screen to fix overlap issues from browser
    console.clear()
    print_banner()
    console.print(f"\n[bold cyan]📁 FILE SHARE SETUP[/bold cyan]\n")
    console.print(f"[green]✓ Selected: {directory}[/green]\n")
    
    # Port
    default_port = str(config.get("port", 8080))
    while True:
        port = ask_robust_int("[yellow]Port[/yellow]", default=default_port)
        
        if port < 1024 or port > 65535:
            console.print("[red]❌ Port must be between 1024 and 65535[/red]")
            continue
            
        if is_port_in_use(port):
            console.print(f"[red]❌ Port {port} is already in use by another application![/red]")
            console.print("[yellow]Please choose a different port.[/yellow]")
        else:
            break
    
    # HTTPS
    default_https = config.get("use_https", True)
    use_https = Confirm.ask("[yellow]Enable HTTPS?[/yellow]", default=default_https)
    
    # Authentication
    console.print("[yellow]Authentication method:[/yellow]")
    console.print("  [cyan]1[/cyan] - Token (recommended, auto-generated secure token)")
    console.print("  [cyan]2[/cyan] - Password (set your own password)")
    console.print("  [cyan]3[/cyan] - None (no authentication)\n")
    
    default_auth = config.get("auth_choice", "1")
    auth_choice = Prompt.ask("Choice", choices=["1", "2", "3"], default=default_auth)
    
    sys_user = get_system_username()
    
    if auth_choice == "1":
        token = generate_access_token()
        password = None
        console.print(f"\n[green]🔑 Login credentials:[/green]")
        console.print(f"  [cyan]Username:[/cyan] {sys_user}")
        console.print(f"  [cyan]Password:[/cyan] [bold]{token}[/bold]")
        console.print("[dim](copy the password/token above)[/dim]\n")
    elif auth_choice == "2":
        console.print("\n[yellow]Set your password:[/yellow]")
        password = input("> ").strip()
        token = None
        if password:
            console.print(f"\n[green]🔑 Login credentials:[/green]")
            console.print(f"  [cyan]Username:[/cyan] {sys_user}")
            console.print(f"  [cyan]Password:[/cyan] {password}\n")
        else:
            console.print("[yellow]⚠️ No password set - open access![/yellow]\n")
    else:
        password = None
        token = None
        console.print("[yellow]⚠️ No authentication - anyone can access![/yellow]\n")
    
    # Timeout
    default_timeout = str(config.get("timeout", 30))
    timeout = ask_robust_int("[yellow]Session timeout (minutes, 0=unlimited)[/yellow]", default=default_timeout)
    
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
    
    console.print("\n[green]✓ Starting server...[/green]\n")
    time.sleep(1)
    
    run_server_with_ui(port, directory, password, token, timeout, use_https)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[cyan]👋 Bye![/cyan]")

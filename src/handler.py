import http.server
import os
import base64
import urllib.parse
from functools import partial
from typing import Optional

from src.state import BLOCK_DURATION_SECONDS
from src.utils import format_size, get_system_username, get_local_ip
from src.security import is_ip_blocked, is_ip_whitelisted, log_access, record_failed_attempt, FAILED_ATTEMPTS

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
        
        # Simple secure filename implementation (no external deps)
        def secure_filename(name):
            # Keep only safe characters
            return "".join([c for c in name if c.isalpha() or c.isdigit() or c in '._-'])
            
        clean_name = secure_filename(os.path.basename(filename))
        if not clean_name:
            return None
            
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
        """Generate custom HTML page with download buttons"""
        
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
                download_btn = f'<a href="{item["download"]}" class="btn btn-zip">📦 ZIP</a>'
            elif not item['is_dir']:
                download_btn = f'<a href="{item["download"]}" download class="btn btn-dl">⬇️ Download</a>'
                if item['preview']:
                    download_btn += f' <button onclick="previewFile(\'{item["href"]}\', \'{item["name"]}\')" class="btn btn-view">👁️ View</button>'
            else:
                download_btn = ''
            
            rows += f'''
            <tr>
                <td><a href="{item['href']}">{item['name']}</a></td>
                <td>{item['size']}</td>
                <td>{download_btn}</td>
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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{
            color: #00d9ff;
            margin-bottom: 10px;
            font-size: 1.5em;
        }}
        .path {{
            color: #888;
            margin-bottom: 20px;
            word-break: break-all;
        }}
        .search-box {{
            padding: 8px 15px;
            border-radius: 20px;
            border: 1px solid rgba(255,255,255,0.2);
            background: rgba(0,0,0,0.2);
            color: white;
            width: 100%;
            max-width: 300px;
            margin-bottom: 20px;
        }}
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
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        th {{
            background: rgba(0,217,255,0.2);
            color: #00d9ff;
        }}
        tr:hover {{ background: rgba(255,255,255,0.05); }}
        a {{ color: #00d9ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        
        .btn {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 5px;
            font-size: 0.85em;
            text-decoration: none !important;
            margin-right: 5px;
            color: #000 !important;
            font-weight: bold;
            cursor: pointer;
            border: none;
        }}
        .btn-dl {{ background: #00d9ff; }}
        .btn-zip {{ background: #ff9800; }}
        .btn-view {{ background: #4caf50; color: white !important; }}
        .btn:hover {{ opacity: 0.8; }}
        
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        
        /* Preview Modal */
        .modal {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 1000; justify-content: center; align-items: center; }}
        .modal-content {{ max-width: 90%; max-height: 90%; background: #222; padding: 20px; border-radius: 10px; position: relative; display: flex; flex-direction: column; }}
        .modal-close {{ position: absolute; top: 10px; right: 15px; color: white; font-size: 24px; cursor: pointer; }}
        .preview-frame {{ width: 80vw; height: 80vh; border: none; background: white; }}
        .preview-img {{ max-width: 100%; max-height: 80vh; object-fit: contain; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 FileShare</h1>
        <p class="path">Path: {path}</p>
        
        <input type="text" id="searchInput" class="search-box" placeholder="🔍 Search files..." onkeyup="filterFiles()">
        
        <form action="{path}" method="post" enctype="multipart/form-data" id="uploadForm">
            <div class="upload-zone" id="dropZone">
                <label for="fileInput" class="upload-label">
                    ☁️ <strong>Drag & Drop files here</strong> or click to upload
                </label>
                <input type="file" name="files" id="fileInput" class="upload-btn" multiple onchange="document.getElementById('uploadForm').submit()">
            </div>
        </form>

        <table id="fileTable">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        <p class="footer">🔒 FileShare v2.0 | {get_system_username()}@{get_local_ip()}</p>
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

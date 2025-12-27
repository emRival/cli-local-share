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
    
    def __init__(self, *args, password=None, token=None, directory=None, allow_upload=False, allow_remove=False, **kwargs):
        self.auth_password = password
        self.auth_token = token
        self.share_directory = directory
        self.allow_upload = allow_upload
        self.allow_remove = allow_remove
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
        """Handle file uploads and deletions"""
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

        # Check for query params (e.g. ?action=delete)
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)
        
        # Handle Deletion
        if query.get('action') == ['delete']:
            if not self.allow_remove:
                self.send_error(403, "Content-Deletion-Forbidden: File deletion is disabled.")
                return
                
            file_to_delete = query.get('file', [''])[0]
            if not file_to_delete:
                self.send_error(400, "Bad Request: No file specified")
                return
            
            # Translate path relative to current directory
            base_dir = self.translate_path(parsed_path.path)
            target_file = os.path.join(base_dir, os.path.basename(file_to_delete))
            
            if os.path.isfile(target_file):
                try:
                    os.remove(target_file)
                    log_access(client_ip, f"🗑️ DELETE: {file_to_delete}", "✅ OK")
                except Exception as e:
                    log_access(client_ip, f"DELETE FAIL: {file_to_delete}", "❌ ERR")
                    self.send_error(500, f"Error deleting file: {e}")
                    return
            
            # Redirect back
            self.send_response(303)
            self.send_header('Location', parsed_path.path)
            self.end_headers()
            return

        # Handle Upload
        if not self.allow_upload:
            self.send_error(403, "Content-Upload-Forbidden: Uploads are disabled.")
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
            
            if uploaded_files:
                log_access(client_ip, f"⬆️ Uploaded: {', '.join(uploaded_files)}", "✅ OK")
                
            self.send_response(303)
            self.send_header('Location', self.path)
            self.end_headers()
            
        except Exception as e:
            log_access(client_ip, "Upload error", "❌ ERR")
            self.send_error(500, f"Upload error: {e}")
    
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
            actions = '<div class="btn-group">'
            
            if item['is_dir'] and item['name'] != '📁 ..':
                # Zip feature placeholder
                actions += f'<a href="{item["download"]}" class="btn btn-zip">📦 ZIP</a>'
            elif not item['is_dir']:
                # Download
                actions += f'<a href="{item["download"]}" download class="btn btn-dl">⬇ DL</a>'
                # Preview
                if item['preview']:
                    actions += f'<button onclick="previewFile(\'{item["href"]}\', \'{item["name"]}\')" class="btn btn-view">👁️ View</button>'
                
                # Delete (Only if enabled)
                if self.allow_remove:
                    actions += f'''
                    <form action="{path}?action=delete&file={item['href']}" method="post" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete {item['name']}?');">
                        <button type="submit" class="btn btn-del" style="color: #ff3333 !important; border-color: rgba(255, 51, 51, 0.3); background: rgba(255, 51, 51, 0.1);">🗑️</button>
                    </form>
                    '''
            
            actions += '</div>'
            
            rows += f'''
            <tr>
                <td><a href="{item['href']}">{item['name']}</a></td>
                <td>{item['size']}</td>
                <td>{actions}</td>
            </tr>
            '''
        
        # Conditional Upload Form
        upload_section = ""
        if self.allow_upload:
            upload_section = f'''
            <form action="{path}" method="post" enctype="multipart/form-data" id="uploadForm">
                <div class="upload-zone" id="dropZone">
                    <input type="file" name="files" id="fileInput" class="upload-btn" multiple onchange="submitUpload()">
                    <label for="fileInput" style="cursor: pointer">
                        <span class="upload-icon">☁️</span>
                        <div class="upload-text">Drag & Drop files here or click to browse</div>
                        <div style="font-size: 0.8em; opacity: 0.6; margin-top: 5px">Max file size: Unlimited</div>
                    </label>
                </div>
            </form>
            '''

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>FileShare - {path}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{ 
            --primary: #00d9ff; 
            --primary-hover: #00b3d6;
            --bg-dark: #121212;
            --glass: rgba(255, 255, 255, 0.05);
            --glass-border: rgba(255, 255, 255, 0.1);
            --text-main: #e0e0e0;
            --text-muted: #a0a0a0;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at top right, #1f2937, #111827);
            color: var(--text-main);
            min-height: 100vh;
            padding: 20px;
            font-size: 15px;
        }}
        
        .container {{ 
            max-width: 1000px; 
            margin: 0 auto; 
            animation: fadeIn 0.5s ease-out;
        }}
        
        @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        
        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        
        h1 {{
            background: linear-gradient(90deg, #00d9ff, #0077ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
            font-size: 1.8rem;
        }}
        
        .path {{
            background: var(--glass);
            border: 1px solid var(--glass-border);
            padding: 12px 20px;
            border-radius: 12px;
            color: var(--text-muted);
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
            backdrop-filter: blur(10px);
        }}
        
        /* Search */
        .search-box {{
            padding: 10px 20px;
            border-radius: 25px;
            border: 1px solid var(--glass-border);
            background: rgba(0,0,0,0.3);
            color: white;
            width: 100%;
            max-width: 300px;
            transition: all 0.3s;
        }}
        .search-box:focus {{
            border-color: var(--primary);
            outline: none;
            box-shadow: 0 0 10px rgba(0, 217, 255, 0.2);
        }}
        
        /* Upload Zone */
        .upload-zone {{
            border: 2px dashed var(--glass-border);
            border-radius: 16px;
            padding: 30px;
            text-align: center;
            margin-bottom: 30px;
            background: var(--glass);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }}
        
        .upload-zone:hover, .upload-zone.dragover {{ 
            border-color: var(--primary); 
            background: rgba(0, 217, 255, 0.05);
            transform: translateY(-2px);
        }}
        
        .upload-icon {{ font-size: 32px; margin-bottom: 10px; display: block; }}
        .upload-text {{ color: var(--text-muted); font-weight: 500; }}
        .upload-btn {{ display: none; }}
        
        /* Table */
        .table-wrapper {{
            background: var(--glass);
            border-radius: 16px;
            border: 1px solid var(--glass-border);
            overflow: hidden;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
        }}
        
        table {{ width: 100%; border-collapse: collapse; min-width: 600px; }}
        
        th {{
            text-align: left;
            padding: 16px 20px;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid var(--glass-border);
            background: rgba(0,0,0,0.2);
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.1em;
        }}
        
        td {{
            padding: 14px 20px;
            border-bottom: 1px solid var(--glass-border);
            transition: background 0.2s;
            vertical-align: middle;
        }}
        
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.03); }}
        
        a {{ color: var(--text-main); text-decoration: none; font-weight: 500; display: flex; align-items: center; gap: 8px; }}
        a:hover {{ color: var(--primary); }}
        
        .file-icon {{ font-size: 1.2em; opacity: 0.8; }}
        
        /* Buttons */
        .btn-group {{ display: flex; gap: 8px; }}
        .btn {{
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 0.8rem;
            border: none;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s;
            text-decoration: none !important;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }}
        
        .btn-dl {{ background: rgba(0, 217, 255, 0.1); color: #00d9ff !important; border: 1px solid rgba(0, 217, 255, 0.2); }}
        .btn-dl:hover {{ background: rgba(0, 217, 255, 0.2); transform: translateY(-1px); }}
        
        .btn-zip {{ background: rgba(255, 152, 0, 0.1); color: #ff9800 !important; border: 1px solid rgba(255, 152, 0, 0.2); }}
        .btn-zip:hover {{ background: rgba(255, 152, 0, 0.2); transform: translateY(-1px); }}
        
        .btn-view {{ background: rgba(76, 175, 80, 0.1); color: #4caf50 !important; border: 1px solid rgba(76, 175, 80, 0.2); }}
        .btn-view:hover {{ background: rgba(76, 175, 80, 0.2); transform: translateY(-1px); }}
        
        .btn-del {{ background: rgba(255, 51, 51, 0.1); color: #ff3333 !important; border: 1px solid rgba(255, 51, 51, 0.2); }}
        .btn-del:hover {{ background: rgba(255, 51, 51, 0.2); transform: translateY(-1px); }}
        
        /* Loading Overlay */
        .loading-overlay {{
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.85);
            backdrop-filter: blur(5px);
            z-index: 2000;
            display: none;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        
        .spinner {{
            width: 50px;
            height: 50px;
            border: 3px solid rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            border-top-color: var(--primary);
            animation: spin 1s ease-in-out infinite;
            margin-bottom: 20px;
        }}
        
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        
        .loading-text {{
            color: white;
            font-size: 1.1rem;
            font-weight: 500;
            letter-spacing: 0.5px;
        }}
        
        /* Preview Modal */
        .modal {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 1000; justify-content: center; align-items: center; backdrop-filter: blur(5px); }}
        .modal-content {{ max-width: 90%; max-height: 90%; background: #1e1e1e; padding: 20px; border-radius: 16px; position: relative; display: flex; flex-direction: column; box-shadow: 0 20px 50px rgba(0,0,0,0.5); border: 1px solid var(--glass-border); }}
        .modal-close {{ position: absolute; top: 15px; right: 20px; color: white; font-size: 24px; cursor: pointer; opacity: 0.7; transition: 0.2s; }}
        .modal-close:hover {{ opacity: 1; }}
        .preview-frame {{ width: 80vw; height: 80vh; border: none; background: white; border-radius: 8px; }}
        .preview-img {{ max-width: 100%; max-height: 80vh; object-fit: contain; border-radius: 8px; }}
        
        .footer {{ margin-top: 40px; text-align: center; color: var(--text-muted); font-size: 0.85em; opacity: 0.7; }}
        
        @media (max-width: 768px) {{
            .header {{ flex-direction: column; align-items: flex-start; }}
            .search-box {{ max-width: 100%; }}
            th, td {{ padding: 12px 15px; }}
            .btn {{ padding: 6px 10px; }}
        }}
    </style>
</head>
<body>
    <!-- Loading Overlay -->
    <div id="loadingOverlay" class="loading-overlay">
        <div class="spinner"></div>
        <div class="loading-text">Uploading files... please wait</div>
    </div>
    
    <div class="container">
        <div class="header">
            <h1>📁 FileShare</h1>
            <input type="text" id="searchInput" class="search-box" placeholder="🔍 Search files..." onkeyup="filterFiles()">
        </div>
        
        <div class="path">
            <span style="opacity:0.5">LOCATION</span> {path}
        </div>
        
        {upload_section}

        <div class="table-wrapper">
            <table id="fileTable">
                <thead>
                    <tr>
                        <th width="35%">Name</th>
                        <th width="15%">Size</th>
                        <th width="50%">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        
        <p class="footer">🔒 Secured by FileShare v3.0 | {get_system_username()}@{get_local_ip()}</p>
    </div>

    <!-- Preview Modal -->
    <div id="previewModal" class="modal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h3 id="previewTitle" style="color:white; margin-bottom:15px; font-weight:500">Preview</h3>
            <div id="previewContainer"></div>
        </div>
    </div>

    <script>
        // Upload & Loading Logic
        function submitUpload() {{
            const fileInput = document.getElementById('fileInput');
            if (fileInput.files.length > 0) {{
                document.getElementById('loadingOverlay').style.display = 'flex';
                document.getElementById('uploadForm').submit();
            }}
        }}

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
            submitUpload();
        }}

        // Preview Logic
        function previewFile(url, name) {{
            let modal = document.getElementById('previewModal');
            let container = document.getElementById('previewContainer');
            let title = document.getElementById('previewTitle');
            
            title.innerText = name;
            container.innerHTML = '<div style="color:white;text-align:center;padding:20px">Loading preview...</div>';
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

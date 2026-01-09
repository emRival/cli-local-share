import http.server
import os
import base64
import urllib.parse
import json
import ssl
from functools import partial
from typing import Optional

from src.state import BLOCK_DURATION_SECONDS, BLOCKED_IPS, STATE_LOCK
from src.utils import format_size, get_system_username, get_local_ip
from src.security import is_ip_blocked, is_ip_whitelisted, log_access, record_failed_attempt, FAILED_ATTEMPTS
from src.share_manager import get_share_manager

def safe_handler(func):
    """Decorator to handle exceptions gracefully"""
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_error(500, f"Internal Server Error: {e}")
            except:
                pass
    return wrapper

class SecureAuthHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler with enhanced security and download UI"""
    
    def __init__(self, *args, password=None, token=None, directory=None, allow_upload=False, allow_remove=False, allow_share_links=False, **kwargs):
        self.auth_password = password
        self.auth_token = token
        self.share_directory = directory
        self.allow_upload = allow_upload
        self.allow_remove = allow_remove
        self.allow_share_links = allow_share_links
        super().__init__(*args, directory=directory, **kwargs)
    
    def log_message(self, format, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        """Custom error page handler"""
        if code == 404:
            self.send_response(404)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Connection', 'close')
            self.end_headers()
            
            html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>404 - File Not Found</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
                <style>
                    :root { --bg-dark: #0f1115; --text-main: #e6edf3; --primary: #3b82f6; --accent: #60a5fa; }
                    body { 
                        background: var(--bg-dark); 
                        color: var(--text-main); 
                        font-family: 'Inter', system-ui, sans-serif; 
                        display: flex; 
                        flex-direction: column; 
                        align-items: center; 
                        justify-content: center; 
                        height: 100vh; 
                        margin: 0; 
                        text-align: center;
                        overflow: hidden;
                    }
                    .container { position: relative; z-index: 10; padding: 20px; }
                    h1 { 
                        font-size: 8rem; 
                        margin: 0; 
                        font-weight: 800;
                        background: linear-gradient(135deg, var(--primary), var(--accent));
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        line-height: 1;
                        margin-bottom: 20px;
                    }
                    h2 { font-size: 2rem; margin: 0 0 10px; font-weight: 600; }
                    p { font-size: 1.1rem; margin: 0 0 30px; opacity: 0.6; max-width: 400px; line-height: 1.5; }
                    .btn { 
                        padding: 14px 32px; 
                        background: var(--primary); 
                        color: white; 
                        text-decoration: none; 
                        border-radius: 50px; 
                        font-weight: 600; 
                        transition: all 0.3s ease;
                        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.4);
                        display: inline-block;
                    }
                    .btn:hover { 
                        transform: translateY(-2px); 
                        box-shadow: 0 8px 25px rgba(59, 130, 246, 0.6); 
                    }
                    .bg-mesh {
                        position: absolute; width: 100%; height: 100%; top: 0; left: 0; z-index: 1;
                        background-image: radial-gradient(circle at 50% 50%, rgba(59, 130, 246, 0.1) 0%, transparent 50%);
                        opacity: 0.5;
                    }
                </style>
            </head>
            <body>
                <div class="bg-mesh"></div>
                <div class="container">
                    <h1>404</h1>
                    <h2>File Not Found</h2>
                    <p>Oops! The file or directory you are looking for seems to have vanished into the digital void.</p>
                    <a href="/" class="btn">Back to Home</a>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        else:
            super().send_error(code, message, explain)
    
    def do_AUTHHEAD(self):
        self.send_response(401)
        import src.state as state
        realm = f'ShareCLI - Session: {state.SESSION_ID} - User: {get_system_username()}'
        self.send_header('WWW-Authenticate', f'Basic realm="{realm}"')
        self.send_header('Content-type', 'text/html; charset=utf-8')
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

    def check_csrf(self) -> bool:
        """Verify request origin to prevent CSRF"""
        # Only check POST/PUT/DELETE
        if self.command not in ['POST', 'PUT', 'DELETE']:
            return True
            
        # Get Origin and Referer
        origin = self.headers.get('Origin')
        referer = self.headers.get('Referer')
        
        # If neither exists, might be a script/curl (allow, mostly safe for local tools)
        # But if they exist, they MUST match our host
        if not origin and not referer:
            return True
            
        host = self.headers.get('Host')
        if not host:
            return False # Host header is mandatory in HTTP/1.1
            
        # Check Origin if present
        if origin:
            # Origin usually includes protocol (http://localhost:8080)
            # Host usually does not (localhost:8080)
            if host not in origin:
                return False
                
        # Check Referer if present
        if referer:
            if host not in referer:
                return False
                
        return True



    def do_POST(self):
        """Handle file uploads and deletions"""
        client_ip = self.client_address[0]
        
        # Security checks
        # 1. Check Auth First (Smart Rate Limit)
        auth_status = self.check_auth()
        
        if auth_status == 1:
            # Success: Unblock if needed
            with STATE_LOCK:
                if client_ip in BLOCKED_IPS:
                    del BLOCKED_IPS[client_ip]
                if client_ip in FAILED_ATTEMPTS:
                    FAILED_ATTEMPTS[client_ip] = 0
        else:
            # Not authenticated: Check Block
            if is_ip_blocked(client_ip):
                self.send_blocked_response()
                return

            if auth_status == 0:
                # Wrong Password
                self.do_AUTHHEAD()
                record_failed_attempt(client_ip)
                log_access(client_ip, "POST", "🔒 AUTH FAILED")
                return
            
            elif auth_status == 2:
                # No Header (First visit)
                self.do_AUTHHEAD()
                return

        # 2. Other Security Checks
        if not self.check_csrf():
            self.send_error(403, "Forbidden: CSRF check failed")
            log_access(client_ip, "CSRF Reject", "🚫 BLOCKED")
            return
            
        if not is_ip_whitelisted(client_ip):
            self.send_whitelist_denied()
            return

        # Check for query params (e.g. ?action=delete)
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)
        
        # Handle Share Link API Endpoints (REQUIRES AUTH)
        if self.path.startswith('/api/share/'):
            # These endpoints return JSON
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            try:
                share_manager = get_share_manager()
                
                # Create Share Link
                if self.path == '/api/share/create':
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    params = json.loads(post_data)
                    
                    file_path = params.get('file_path')
                    expiry_hours = int(params.get('expiry_hours', 24))
                    max_downloads = int(params.get('max_downloads', 0))
                    pin = params.get('pin')
                    
                    # Generate share link
                    link_info = share_manager.generate_share_link(
                        file_path=file_path,
                        expiry_hours=expiry_hours,
                        max_downloads=max_downloads,
                        pin=pin,
                        creator_ip=client_ip
                    )
                    
                    # Build full share URL
                    host = self.headers.get('Host', get_local_ip() + ':8080')
                    protocol = 'https' if isinstance(self.connection, ssl.SSLSocket) else 'http'
                    share_url = f"{protocol}://{host}/s/{link_info['token']}"
                    
                    response = {
                        'success': True,
                        'share_url': share_url,
                        'token': link_info['token'],
                        'expires_at': link_info['expires_at'],
                        'max_downloads': link_info['max_downloads'],
                        'has_pin': link_info['has_pin']
                    }
                    
                    self.wfile.write(json.dumps(response).encode())
                    log_access(client_ip, f"CREATE SHARE: {file_path}", "🔗 CREATED")
                    return
                
                # Revoke Share Link
                elif self.path == '/api/share/revoke':
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    params = json.loads(post_data)
                    
                    token = params.get('token')
                    success = share_manager.revoke_link(token)
                    
                    response = {
                        'success': success
                    }
                    
                    self.wfile.write(json.dumps(response).encode())
                    log_access(client_ip, f"REVOKE SHARE: {token}", "🔗 REVOKED")
                    return
                
            except Exception as e:
                error_response = {
                    'success': False,
                    'error': str(e)
                }
                self.wfile.write(json.dumps(error_response).encode())
                return
        
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
                    log_access(client_ip, f"🗑️ DELETE: {file_to_delete}", "🗑️ DELETED")
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
        content_type_header = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type_header:
            self.send_error(400, "Bad Request: Must be multipart/form-data")
            return
            
        boundary = None
        if 'boundary=' in content_type_header:
            boundary = content_type_header.split('boundary=')[1].strip().strip('"').strip("'")
            if not boundary:
                self.send_error(400, "Bad Request: Invalid boundary")
                return
        else:
            self.send_error(400, "Bad Request: Missing boundary")
            return

        try:
            # Streaming Parser logic with Content-Length tracking (Fix for Keep-Alive Hang)
            content_length = int(self.headers.get('content-length', 0))
            if content_length == 0:
                self.send_error(400, "Bad Request: Missing Content-Length")
                return

            boundary_bytes = ('--' + boundary).encode()
            uploaded_files = []
            
            # Wrapper to read exactly content_length bytes
            bytes_read = 0
            
            # Helper to read line with accounting
            def safe_readline():
                nonlocal bytes_read
                if bytes_read >= content_length:
                    return b""
                line = self.rfile.readline()
                bytes_read += len(line)
                return line

            # Helper to read chunk with accounting
            def safe_read(size):
                nonlocal bytes_read
                if bytes_read >= content_length:
                    return b""
                to_read = min(size, content_length - bytes_read)
                chunk = self.rfile.read(to_read)
                bytes_read += len(chunk)
                return chunk
            
            # 1. Read preamble (until first boundary)
            line = safe_readline()
            while line and boundary_bytes not in line:
                line = safe_readline()
            
            # Now we are at a boundary
            while bytes_read < content_length:
                # Read Headers
                headers = {}
                header_line = safe_readline()
                if not header_line:
                    break 
                
                # Check for end boundary (--boundary--)
                if header_line.strip() == boundary_bytes + b'--':
                    break

                while True:
                    if not header_line or header_line == b'\r\n':
                        break
                    line_str = header_line.decode('utf-8', 'ignore')
                    if ':' in line_str:
                        key, val = line_str.split(':', 1)
                        headers[key.lower().strip()] = val.strip()
                    header_line = safe_readline()
                
                if not headers:
                     break
                
                # Check for filename
                disposition = headers.get('content-disposition', '')
                filename = None
                if 'filename=' in disposition:
                    filename = disposition.split('filename=')[1].split(';')[0].strip('"').strip("'")
                
                if filename:
                    # It's a file
                    upload_path = self.get_upload_path(filename)
                    if upload_path:
                        # Stream Data
                        with open(upload_path, 'wb') as f:
                            prev_chunk = b''
                            while bytes_read < content_length:
                                chunk = safe_read(65536) # 64KB
                                if not chunk:
                                    break
                                
                                buffer = prev_chunk + chunk
                                if boundary_bytes in buffer:
                                    # Boundary found!
                                    part_data, rest = buffer.split(boundary_bytes, 1)
                                    
                                    # Write data up to boundary
                                    # Strip trailing \r\n
                                    to_write = part_data
                                    if to_write.endswith(b'\r\n'):
                                        to_write = to_write[:-2]
                                    elif to_write.endswith(b'\n'):
                                        to_write = to_write[:-1]
                                    
                                    f.write(to_write)
                                    
                                    # Since we are implementing a simplified one-file-at-a-time fix
                                    # and we consumed the boundary in 'buffer', 
                                    # we are technically overlapping into the next part/epilogue.
                                    # But since we track content-length, we will eventually stop.
                                    
                                    # For robustness in this fix, we assume single file or we stop here.
                                    break 
                                else:
                                    # Margin check for boundary
                                    margin = len(boundary_bytes) + 2
                                    if len(buffer) > margin:
                                        write_len = len(buffer) - margin
                                        f.write(buffer[:write_len])
                                        prev_chunk = buffer[write_len:]
                                    else:
                                        prev_chunk = buffer
                            
                        uploaded_files.append(os.path.basename(upload_path))
                        break # Stop after first file for stability
                
                break # Break outer loop if no filename or done
            
            if uploaded_files:
                log_access(client_ip, f"⬆️ Uploaded: {', '.join(uploaded_files)}", "✅ UPLOAD")
                
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
    
    def check_auth(self) -> int:
        """
        Check authentication
        Returns:
            0: Authentication Failed (Wrong Password)
            1: Authentication Successful
            2: No Authentication Provided (First visit / Cancel)
        """
        if not self.auth_password and not self.auth_token:
            return 1 # No auth required
        
        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            return 2 # No credentials provided
        
        try:
            auth_type, auth_data = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return 0
            
            decoded = base64.b64decode(auth_data).decode('utf-8')
            username, password = decoded.split(':', 1)
            
            # Check password or token
            if self.auth_password and password == self.auth_password:
                return 1
            if self.auth_token and password == self.auth_token:
                return 1
            
            return 0 # Wrong password
        except:
            return 0
    
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
            can_preview = ext in [
                '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp',
                '.mp4', '.webm', '.ogg', '.mov', 
                '.mp3', '.wav', '.m4a',
                '.txt', '.md', '.py', '.log', '.json', '.css', '.html', '.js', '.sh', '.xml', '.yml', '.yaml'
            ]
            
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
        import html
        rows = ""
        for item in items:
            actions = '<div class="btn-group">'
            safe_display_name = html.escape(item['name'])
            # Escape for JS string context (basic)
            js_safe_name = item['name'].replace("'", "\\'").replace('"', '&quot;')
            
            if item['is_dir'] and item['name'] != '📁 ..':
                # Zip feature placeholder
                actions += f'<a href="{item["download"]}" class="btn btn-zip">📦 ZIP</a>'
            elif not item['is_dir']:
                # Download
                actions += f'<a href="{item["download"]}" download class="btn btn-dl">⬇ DL</a>'
                
                # Share Link (Only if enabled)
                if self.allow_share_links:
                    file_full_path = os.path.join(full_path, item['name'].replace('📄 ', ''))
                    file_basename = os.path.basename(file_full_path)
                    actions += f'<button onclick="openShareModal(\'{file_full_path}\', \'{js_safe_name.replace("📄 ", "")}\')" class="btn btn-share">🔗 Share</button>'
                
                # Preview
                if item['preview']:
                    actions += f'<button onclick="previewFile(\'{item["href"]}\', \'{js_safe_name}\')" class="btn btn-view">👁️ View</button>'
                
                # Delete (Only if enabled)
                if self.allow_remove:
                    # Escape name for JS
                    safe_name = item['name'].replace("'", "\\'")
                    actions += f'''
                    <button onclick="deleteFile('{item['href']}', '{safe_name}')" class="btn btn-del">🗑️ Delete</button>
                    '''
            
            rows += f"""
            <tr>
                <td><a href="{item['href']}" class="{'' if item['is_dir'] else 'file-link'}">{safe_display_name}</a></td>
                <td>{item['size']}</td>
                <td>{actions}</div></td>
            </tr>
            """
        
        # Conditional Upload Form
        upload_section = ""
        if self.allow_upload:
            upload_section = f'''
            <div class="upload-zone" id="dropZone">
                <input type="file" name="files" id="fileInput" class="upload-btn" multiple onchange="uploadFiles(this.files)">
                <label for="fileInput" style="cursor: pointer">
                    <span class="upload-icon">☁️</span>
                    <div class="upload-text">Drag & Drop files here or click to browse</div>
                    <div style="font-size: 0.8em; opacity: 0.6; margin-top: 5px">Max file size: Unlimited</div>
                </label>
            </div>
            '''

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ShareCLI - {path}</title>
    <link rel="icon" type="image/svg+xml" href="../assets/logo_cli.svg">
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
            /* Scrollable Container */
            max-height: 65vh;
            overflow-y: auto;
            position: relative;
        }}
        
        table {{ width: 100%; border-collapse: collapse; }}
        
        th {{
            position: sticky;
            top: 0;
            z-index: 10;
            text-align: left;
            padding: 16px 20px;
            color: var(--text-muted);
            font-weight: 600;
            border-bottom: 1px solid var(--glass-border);
            background: rgba(31, 41, 55, 0.95); /* Match theme opaque for sticky */
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.1em;
            backdrop-filter: blur(5px);
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
        
        .btn-share {{ background: rgba(139, 92, 246, 0.1); color: #8b5cf6 !important; border: 1px solid rgba(139, 92, 246, 0.2); }}
        .btn-share:hover {{ background: rgba(139, 92, 246, 0.2); transform: translateY(-1px); }}
        
        /* Share Modal */
        .share-modal {{ 
            display: none; 
            position: fixed; 
            top: 0; 
            left: 0; 
            width: 100%; 
            height: 100%; 
            background: rgba(0,0,0,0.9); 
            z-index: 2000; 
            justify-content: center; 
            align-items: center; 
            backdrop-filter: blur(5px); 
        }}
        .share-modal-content {{ 
            max-width: 500px; 
            width: 90%; 
            background: #1e1e1e; 
            padding: 2rem; 
            border-radius: 16px; 
            position: relative; 
            box-shadow: 0 20px 50px rgba(0,0,0,0.5); 
            border: 1px solid var(--glass-border); 
        }}
        .share-modal-close {{ 
            position: absolute; 
            top: 15px; 
            right: 20px; 
            color: white; 
            font-size: 24px; 
            cursor: pointer; 
            opacity: 0.7; 
            transition: 0.2s; 
        }}
        .share-modal-close:hover {{ opacity: 1; }}
        .share-modal h3 {{ color: white; margin-bottom: 1.5rem; font-weight: 500; }}
        .share-form-group {{ margin-bottom: 1.2rem; }}
        .share-form-group label {{ 
            display: block; 
            color: var(--text-muted); 
            margin-bottom: 0.5rem; 
            font-size: 0.9rem; 
        }}
        .share-form-group select,
        .share-form-group input[type="text"] {{
            width: 100%;
            padding: 10px 15px;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--glass-border);
            border-radius: 8px;
            color: white;
            font-size: 0.95rem;
        }}
        .share-form-group input[type="checkbox"] {{
            margin-right: 8px;
        }}
        .share-btn-primary {{
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
            border: none;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }}
        .share-btn-primary:hover {{ transform: translateY(-2px); box-shadow: 0 6px 20px rgba(139, 92, 246, 0.4); }}
        .share-result {{
            display: none;
            margin-top: 1.5rem;
            padding: 1.5rem;
            background: rgba(139, 92, 246, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(139, 92, 246, 0.3);
        }}
        .share-result h4 {{ color: #8b5cf6; margin-bottom: 1rem; }}
        .share-url-container {{
            display: flex;
            gap: 10px;
            margin-bottom: 1rem;
        }}
        .share-url {{ 
            flex: 1; 
            padding: 10px; 
            background: rgba(0,0,0,0.3); 
            border: 1px solid var(--glass-border); 
            border-radius: 6px; 
            color: white; 
            font-family: monospace; 
            font-size: 0.85rem; 
        }}
        .share-info {{ color: var(--text-muted); font-size: 0.9rem; line-height: 1.8; }}
        
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
        
        /* Share Links Dashboard Spacing */
        .share-links-dashboard {{
            margin-bottom: 2rem;
        }}
        
        /* Logout Button */
        .logout-btn {{
            padding: 10px 20px;
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(220, 38, 38, 0.15) 100%);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 12px;
            color: #fca5a5 !important;
            text-decoration: none;
            font-weight: 600;
            font-size: 0.9rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .logout-btn:hover {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.25) 0%, rgba(220, 38, 38, 0.25) 100%);
            border-color: rgba(239, 68, 68, 0.5);
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(239, 68, 68, 0.3);
            color: #ff6b6b !important;
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
            margin-bottom: 15px;
        }}

        .progress-container {{
            width: 300px;
            height: 6px;
            background: rgba(255,255,255,0.1);
            border-radius: 3px;
            overflow: hidden;
            display: none; /* Hidden by default */
        }}
        
        .progress-bar {{
            height: 100%;
            background: var(--primary);
            width: 0%;
            transition: width 0.2s linear;
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
            .container {{ padding: 10px; width: 100%; }}
            .header {{ flex-direction: column; align-items: stretch; gap: 15px; }}
            .search-box {{ max-width: 100%; font-size: 16px; padding: 12px 20px; }}
            
            h1 {{ text-align: center; font-size: 1.5rem; }}
            
            .table-wrapper {{ max-height: 75vh; }}
            
            /* Responsive Cards */
            table {{ display: block; }}
            thead {{ display: none; }} /* Hide Header */
            tbody {{ display: block; }}
            
            tr {{ 
                display: flex;
                flex-direction: column;
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid var(--glass-border);
                border-radius: 12px; 
                margin-bottom: 12px;
                padding: 15px;
                gap: 5px;
            }}
            
            td {{ 
                display: block; 
                border: none !important;
                padding: 0 !important;
            }}
            
            /* Name */
            td:nth-child(1) {{
                font-size: 1.1rem;
                font-weight: 600;
                margin-bottom: 8px;
                word-wrap: break-word;      /* Legacy support */
                overflow-wrap: break-word;  /* Standard property */
                word-break: break-word;     /* Ensure long words break */
                line-height: 1.5;
            }}
            
            /* Size */
            td:nth-child(2) {{
                color: var(--text-muted);
                font-size: 0.85rem;
                margin-bottom: 15px;
            }}
            
            /* Actions */
            td:nth-child(3) {{
                margin-top: 5px;
                width: 100%;
            }}
            
            .btn-group {{ 
                display: flex;
                flex-direction: column; /* Stack buttons vertically */
                gap: 12px; 
                width: 100%;
            }}
            
            .btn-group .btn {{
                width: 100%;
                justify-content: center;
                padding: 14px; /* Larger touch target */
                font-size: 1rem;
            }}
            
            .upload-zone {{ padding: 20px; }}
            .footer {{ margin-bottom: 30px; }}
        }}
    </style>
</head>
<body>
    <!-- Loading Overlay -->
    <div id="loadingOverlay" class="loading-overlay">
        <div class="spinner"></div>
        <div class="loading-text" id="loadingText">Processing...</div>
        <div class="progress-container" id="progressContainer">
            <div class="progress-bar" id="progressBar"></div>
        </div>
        <div id="progressPercent" style="color: #888; margin-top: 5px; font-size: 0.9em;"></div>
    </div>
    
    <div class="container">
        <div class="header">
            <h1>📁 ShareCLI</h1>
            <div style="display:flex;gap:10px;align-items:center">
                <input type="text" id="searchInput" class="search-box" placeholder="🔍 Search files..." onkeyup="filterFiles()">
                <a href="/logout" class="logout-btn">🚪 Logout</a>
            </div>
        </div>
        
        <div class="path">
            <span style="opacity:0.5">LOCATION</span> {path}
        </div>
        
        {upload_section}

        <!-- Active Share Links Dashboard (Only if sharing is enabled) -->
        {f'''
        <div class="share-links-dashboard" id="shareLinksSection" style="display: {'block' if self.allow_share_links else 'none'};">
            <h3 style="color: white; margin-bottom: 1rem; display: flex; align-items: center; gap: 10px;">
                🔗 Active Share Links 
                <span id="linkCount" style="font-size: 0.9rem; color: var(--text-muted);">(0)</span>
                <button onclick="refreshShareLinks()" class="btn btn-dl" style="margin-left: auto; font-size: 0.85rem; padding: 8px 16px;">🔄 Refresh</button>
            </h3>
            <div class="table-wrapper">
                <table id="shareLinksTable">
                    <thead>
                        <tr>
                            <th width="30%">File</th>
                            <th width="18%">Created</th>
                            <th width="18%">Expires</th>
                            <th width="15%">Downloads</th>
                            <th width="19%">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="shareLinksBody">
                        <tr>
                            <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                                Loading share links...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        ''' if self.allow_share_links else ''}

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
        
        <p class="footer">🔒 Secured by ShareCLI v2.0 | {get_system_username()}@{get_local_ip()}</p>
    </div>

    <!-- Preview Modal -->
    <div id="previewModal" class="modal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h3 id="previewTitle" style="color:white; margin-bottom:15px; font-weight:500">Preview</h3>
            <div id="previewContainer"></div>
        </div>
    </div>

    <!-- Share Link Modal -->
    <div id="shareModal" class="share-modal">
        <div class="share-modal-content">
            <span class="share-modal-close" onclick="closeShareModal()">&times;</span>
            <h3>🔗 Create Share Link</h3>
            <div id="shareFormContainer">
                <p style="color: #a1a1aa; margin-bottom: 1.5rem;" id="shareFileName"></p>
                
                <div class="share-form-group">
                    <label>Expires After:</label>
                    <select id="expiryTime">
                        <option value="1">1 hour</option>
                        <option value="6">6 hours</option>
                        <option value="24" selected>24 hours (recommended)</option>
                        <option value="168">7 days</option>
                    </select>
                </div>
                
                <div class="share-form-group">
                    <label>Max Downloads:</label>
                    <select id="maxDownloads">
                        <option value="1">One-time download</option>
                        <option value="0" selected>Unlimited (until expiry)</option>
                        <option value="5">5 downloads</option>
                        <option value="10">10 downloads</option>
                    </select>
                </div>
                
                <div class="share-form-group">
                    <label>
                        <input type="checkbox" id="enablePin" onchange="togglePinInput()"> Protect with PIN
                    </label>
                    <input type="text" id="pinCode" placeholder="Enter 4-6 digit PIN" maxlength="6" pattern="[0-9]*" style="display:none; margin-top:10px;">
                </div>
                
                <button class="share-btn-primary" onclick="generateShareLink()">Generate Share Link</button>
            </div>
            
            <div id="shareResult" class="share-result">
                <h4>✅ Link Created Successfully!</h4>
                <div class="share-url-container">
                    <input type="text" id="shareUrlInput" class="share-url" readonly>
                    <button class="btn btn-dl" onclick="copyShareLink()" style="flex-shrink:0;">📋 Copy</button>
                </div>
                <div class="share-info" id="shareInfo"></div>
            </div>
        </div>
    </div>

    <script>
        // Upload Logic (XHR for Progress)
        function uploadFiles(files) {{
            if (files.length === 0) return;
            
            const overlay = document.getElementById('loadingOverlay');
            const progressContainer = document.getElementById('progressContainer');
            const progressBar = document.getElementById('progressBar');
            const progressPercent = document.getElementById('progressPercent');
            const loadingText = document.getElementById('loadingText');
            
            overlay.style.display = 'flex';
            progressContainer.style.display = 'block';
            loadingText.innerText = "Uploading " + files.length + " file(s)...";
            
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {{
                formData.append('files', files[i]);
            }}
            
            const xhr = new XMLHttpRequest();
            xhr.open('POST', window.location.href, true);
            
            xhr.upload.onprogress = function(e) {{
                if (e.lengthComputable) {{
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressBar.style.width = percentComplete + '%';
                    progressPercent.innerText = Math.round(percentComplete) + '%';
                }}
            }};
            
            xhr.onload = function() {{
                if (xhr.status === 200 || xhr.status === 303) {{
                    loadingText.innerText = "✅ Upload Complete!";
                    progressBar.style.width = '100%';
                    setTimeout(() => window.location.reload(), 500);
                }} else {{
                    alert("Upload failed: " + xhr.statusText);
                    overlay.style.display = 'none';
                }}
            }};
            
            xhr.onerror = function() {{
                alert("Upload failed (Network Error)");
                overlay.style.display = 'none';
            }};
            
            xhr.send(formData);
        }}

        // Delete Logic (Fetch)
        function deleteFile(url, name) {{
            if (!confirm('Are you sure you want to delete ' + name + '?')) return;
            
            const overlay = document.getElementById('loadingOverlay');
            const loadingText = document.getElementById('loadingText');
            const progressContainer = document.getElementById('progressContainer');
            
            overlay.style.display = 'flex';
            progressContainer.style.display = 'none'; // No progress bar for delete
            loadingText.innerText = "Deleting " + name + "...";
            
            // Fix: Post to current page directory with query params
            // 'url' passed here is item['href'] which is already URL-encoded
            const deleteUrl = window.location.pathname + '?action=delete&file=' + url;
            
            fetch(deleteUrl, {{ method: 'POST' }})
            .then(response => {{
                if (response.ok || response.status === 303) {{
                    loadingText.innerText = "🗑️ Deleted!";
                    setTimeout(() => window.location.reload(), 500);
                }} else {{
                    alert("Delete failed!");
                    overlay.style.display = 'none';
                }}
            }})
            .catch(err => {{
                alert("Delete error: " + err);
                overlay.style.display = 'none';
            }});
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

        // Logic to clear Basic Auth credentials
        function logout() {{
            if (!confirm('Are you sure you want to logout?')) return;
            
            // Fast logout: Directly redirect to logout endpoint
            window.location.href = '/logout';
        }}

        function closeModal(e) {{
            if (e) e.stopPropagation();
            document.getElementById('previewModal').style.display = 'none';
        }}

        // Share Link Functions
        let currentShareFilePath = '';
        let currentShareFileName = '';

        function openShareModal(filePath, fileName) {{
            currentShareFilePath = filePath;
            currentShareFileName = fileName;
            
            document.getElementById('shareFileName').textContent = fileName;
            document.getElementById('shareFormContainer').style.display = 'block';
            document.getElementById('shareResult').style.display = 'none';
            document.getElementById('shareModal').style.display = 'flex';
            
            // Reset form
            document.getElementById('expiryTime').value = '24';
            document.getElementById('maxDownloads').value = '0';
            document.getElementById('enablePin').checked = false;
            document.getElementById('pinCode').style.display = 'none';
            document.getElementById('pinCode').value = '';
        }}

        function closeShareModal() {{
            document.getElementById('shareModal').style.display = 'none';
        }}

        function togglePinInput() {{
            const checkbox = document.getElementById('enablePin');
            const pinInput = document.getElementById('pinCode');
            pinInput.style.display = checkbox.checked ? 'block' : 'none';
            if (!checkbox.checked) {{
                pinInput.value = '';
            }}
        }}

        async function generateShareLink() {{
            const expiryHours = parseInt(document.getElementById('expiryTime').value);
            const maxDownloads = parseInt(document.getElementById('maxDownloads').value);
            const enablePin = document.getElementById('enablePin').checked;
            const pin = enablePin ? document.getElementById('pinCode').value : null;

            // Validate PIN
            if (enablePin && (!pin || pin.length < 4)) {{
                alert('Please enter a valid PIN (4-6 digits)');
                return;
            }}

            try {{
                const response = await fetch('/api/share/create', {{
                    method: 'POST',
                    credentials: 'include',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{
                        file_path: currentShareFilePath,
                        expiry_hours: expiryHours,
                        max_downloads: maxDownloads,
                        pin: pin
                    }})
                }});

                const data = await response.json();

                if (data.success) {{
                    // Show result
                    document.getElementById('shareFormContainer').style.display = 'none';
                    document.getElementById('shareResult').style.display = 'block';
                    document.getElementById('shareUrlInput').value = data.share_url;
                    
                    // Format expiry time
                    const expiryDate = new Date(data.expires_at);
                    const expiryStr = expiryDate.toLocaleString();
                    
                    const downloadLimit = data.max_downloads === 0 ? '∞' : data.max_downloads;
                    const pinInfo = data.has_pin ? `<br>🔐 PIN: <strong>${{pin}}</strong>` : '';
                    
                    document.getElementById('shareInfo').innerHTML = `
                        📅 Expires: <strong>${{expiryStr}}</strong><br>
                        ⬇️ Downloads: <strong>0 / ${{downloadLimit}}</strong>${{pinInfo}}<br><br>
                        <button onclick="closeShareModal(); loadShareLinks();" class="btn btn-dl" style="padding: 10px 20px;">✅ Close</button>
                        <button onclick="document.getElementById('shareFormContainer').style.display='block'; document.getElementById('shareResult').style.display='none';" class="btn btn-share" style="padding: 10px 20px; margin-left: 10px;">🔗 Create Another</button>
                    `;
                    
                    // Refresh dashboard to show new link
                    if (typeof loadShareLinks === 'function') {{
                        setTimeout(() => loadShareLinks(), 500);
                    }}
                }} else {{
                    alert('Error creating share link: ' + data.error);
                }}
            }} catch (error) {{
                console.error('Error in generateShareLink:', error);
                alert('Failed to create share link: ' + error);
            }}
        }}

        function copyShareLink() {{
            const input = document.getElementById('shareUrlInput');
            input.select();
            document.execCommand('copy');
            
            // Visual feedback
            const btn = event.target;
            const originalText = btn.innerHTML;
            btn.innerHTML = '✅ Copied!';
            btn.style.background = 'rgba(16, 185, 129, 0.2)';
            
            setTimeout(() => {{
                btn.innerHTML = originalText;
                btn.style.background = '';
            }}, 2000);
        }}

        // Active Share Links Dashboard Functions
        async function loadShareLinks() {{
            console.log('[DEBUG] loadShareLinks called');
            try {{
                const response = await fetch('/api/share/list', {{
                    credentials: 'include'  // Include authentication credentials
                }});
                console.log('[DEBUG] API Response status:', response.status);
                const data = await response.json();
                console.log('[DEBUG] API Data:', data);
                
                if (data.success) {{
                    const tbody = document.getElementById('shareLinksBody');
                    const linkCount = document.getElementById('linkCount');
                    const links = data.links || [];
                    
                    console.log('[DEBUG] Links count:', links.length);
                    console.log('[DEBUG] Links data:', links);
                    
                    linkCount.textContent = `(${{links.length}})`;
                    
                    if (links.length === 0) {{
                        tbody.innerHTML = `
                            <tr>
                                <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">
                                    No active share links. Create one by clicking 🔗 Share button on any file.
                                </td>
                            </tr>
                        `;
                        return;
                    }}
                    
                    tbody.innerHTML = links.map(link => {{
                        const createdDate = new Date(link.created_at);
                        const expiresDate = new Date(link.expires_at);
                        const now = new Date();
                        const isExpiringSoon = (expiresDate - now) < 3600000; // Less than 1 hour
                        const downloadText = link.max_downloads === 0 ? '∞' : link.max_downloads;
                        const expiresClass = isExpiringSoon ? 'style="color: #fbbf24;"' : '';
                        
                        return `
                            <tr>
                                <td>📄 ${{link.file_name}}</td>
                                <td>${{formatDate(createdDate)}}</td>
                                <td ${{expiresClass}}>${{formatDate(expiresDate)}}</td>
                                <td>${{link.download_count}} / ${{downloadText}}</td>
                                <td>
                                    <div style="display: flex; gap: 8px;">
                                        <button onclick="copyToClipboard('/s/${{link.token}}')" class="btn btn-dl" style="font-size: 0.85rem; padding: 6px 12px;">📋 Copy</button>
                                        <button onclick="revokeShareLink('${{link.token}}')" class="btn btn-del" style="font-size: 0.85rem; padding: 6px 12px;">🗑️ Revoke</button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    }}).join('');
                    
                    console.log('[DEBUG] Table updated successfully');
                }} else {{
                    console.error('[DEBUG] API returned success=false');
                }}
            }} catch (error) {{
                console.error('[DEBUG] Failed to load share links:', error);
            }}
        }}

        function refreshShareLinks() {{
            loadShareLinks();
        }}

        async function revokeShareLink(token) {{
            if (!confirm('Are you sure you want to revoke this share link? It will no longer be accessible.')) {{
                return;
            }}
            
            try {{
                const response = await fetch('/api/share/revoke', {{
                    method: 'POST',
                    credentials: 'include',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ token: token }})
                }});
                
                const data = await response.json();
                
                if (data.success) {{
                    // Reload share links
                    loadShareLinks();
                }} else {{
                    alert('Failed to revoke link');
                }}
            }} catch (error) {{
                alert('Error: ' + error);
            }}
        }}

        function copyToClipboard(path) {{
            const url = window.location.origin + path;
            const input = document.createElement('textarea');
            input.value = url;
            document.body.appendChild(input);
            input.select();
            document.execCommand('copy');
            document.body.removeChild(input);
            
            // Visual feedback
            const btn = event.target;
            const originalText = btn.innerHTML;
            btn.innerHTML = '✅ Copied!';
            setTimeout(() => {{ btn.innerHTML = originalText; }}, 1500);
        }}

        function formatDate(date) {{
            // Ensure date is a Date object
            if (!(date instanceof Date) || isNaN(date.getTime())) {{
                return 'Invalid date';
            }}
            
            // Show short date format: MM/DD HH:MM or relative if recent
            const now = new Date();
            const diffMs = now - date; // Positive if date is in the past
            const diffMins = Math.floor(Math.abs(diffMs) / 60000);
            const diffHours = Math.floor(Math.abs(diffMs) / 3600000);
            
            // If less than 5 minutes, show "just now"
            if (diffMins < 5 && diffMs >= 0) {{
                return 'Just now';
            }}
            
            // If less than 1 hour, show minutes
            if (diffHours < 1) {{
                if (diffMs >= 0) {{
                    return `${{diffMins}}m ago`;
                }} else {{
                    return `In ${{diffMins}}m`;
                }}
            }}
            
            // If within 24 hours, show hours
            if (diffHours < 24) {{
                if (diffMs >= 0) {{
                    return `${{diffHours}}h ago`;
                }} else {{
                    return `In ${{diffHours}}h`;
                }}
            }}
            
            // Otherwise show actual date/time
            const month = date.getMonth() + 1;
            const day = date.getDate();
            const hour = date.getHours().toString().padStart(2, '0');
            const minute = date.getMinutes().toString().padStart(2, '0');
            
            return `${{month}}/${{day}} ${{hour}}:${{minute}}`;
        }}

        // Auto-refresh share links every 10 seconds if dashboard exists
        if (document.getElementById('shareLinksBody')) {{
            loadShareLinks(); // Initial load
            setInterval(loadShareLinks, 10000); // Refresh every 10 seconds
        }}
        
        
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
    
    def _generate_error_page(self, title, message):
        """Generate a modern error page for share links."""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{title} - ShareCLI</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background-color: #050505;
                    color: #ffffff;
                    display: flex; 
                    align-items: center; 
                    justify-content: center; 
                    min-height: 100vh; 
                    text-align: center;
                }}
                .bg-mesh {{
                    position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1;
                    background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #050505 70%);
                }}
                .card {{ 
                    background: rgba(20, 20, 20, 0.6);
                    backdrop-filter: blur(20px);
                    padding: 3rem 2.5rem;
                    border-radius: 20px;
                    border: 1px solid rgba(255,255,255,0.1);
                    max-width: 90%;
                    width: 450px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                }}
                .icon {{ font-size: 4rem; margin-bottom: 1.5rem; }}
                h1 {{ 
                    margin-bottom: 1rem;
                    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    font-weight: 700;
                    font-size: 2rem;
                }}
                p {{ margin-bottom: 2rem; color: #a1a1aa; font-size: 1.05rem; }}
                .footer {{ margin-top: 2rem; font-size: 0.85rem; color: #71717a; }}
            </style>
        </head>
        <body>
            <div class="bg-mesh"></div>
            <div class="card">
                <div class="icon">⚠️</div>
                <h1>{title}</h1>
                <p>{message}</p>
                <div class="footer">ShareCLI v2.0</div>
            </div>
        </body>
        </html>
        """
    
    def _generate_pin_page(self, token, filename, error=False):
        """Generate PIN input page for protected share links."""
        error_message = ""
        shake_animation = ""
        error_class = ""
        
        if error:
            error_message = '<p style="color: #ef4444; margin-bottom: 1rem; font-weight: 600;">❌ Incorrect PIN. Please try again.</p>'
            shake_animation = """
                @keyframes shake {{
                    0%, 100% {{ transform: translateX(0); }}
                    10%, 30%, 50%, 70%, 90% {{ transform: translateX(-5px); }}
                    20%, 40%, 60%, 80% {{ transform: translateX(5px); }}
                }}
                .shake {{ animation: shake 0.5s; }}
            """
            error_class = "shake"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Enter PIN - ShareCLI</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background-color: #050505;
                    color: #ffffff;
                    display: flex; 
                    align-items: center; 
                    justify-content: center; 
                    min-height: 100vh; 
                    text-align: center;
                }}
                .bg-mesh {{
                    position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; z-index: -1;
                    background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #050505 70%);
                }}
                .card {{ 
                    background: rgba(20, 20, 20, 0.6);
                    backdrop-filter: blur(20px);
                    padding: 3rem 2.5rem;
                    border-radius: 20px;
                    border: 1px solid rgba(255,255,255,0.1);
                    max-width: 90%;
                    width: 450px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                }}
                .icon {{ font-size: 4rem; margin-bottom: 1.5rem; }}
                h1 {{ 
                    margin-bottom: 0.5rem;
                    background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    font-weight: 700;
                    font-size: 2rem;
                }}
                p {{ margin-bottom: 2rem; color: #a1a1aa; font-size: 1.05rem; }}
                input {{
                    width: 100%;
                    max-width: 200px;
                    padding: 14px 20px;
                    font-size: 1.5rem;
                    text-align: center;
                    border: 1px solid rgba(255,255,255,0.2);
                    background: rgba(255,255,255,0.05);
                    color: #fff;
                    border-radius: 10px;
                    margin-bottom: 1.5rem;
                    letter-spacing: 0.5rem;
                }}
                input:focus {{ outline: none; border-color: #fbbf24; }}
                button {{
                    color: #000;
                    font-weight: 600;
                    padding: 14px 32px;
                    background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
                    border: none;
                    border-radius: 10px;
                    font-size: 16px;
                    cursor: pointer;
                    box-shadow: 0 4px 15px rgba(251, 191, 36, 0.3);
                    width: 100%;
                    max-width: 200px;
                }}
                button:hover {{ transform: translateY(-2px); box-shadow: 0 6px 25px rgba(251, 191, 36, 0.5); }}
                .footer {{ margin-top: 2rem; font-size: 0.85rem; color: #71717a; }}
                {shake_animation}
            </style>
        </head>
        <body>
            <div class="bg-mesh"></div>
            <div class="card {error_class}">
                <div class="icon">🔐</div>
                <h1>Protected File</h1>
                {error_message}
                <p><strong>{filename}</strong><br>This file is PIN-protected. Enter the PIN to download.</p>
                <form method="GET" action="/s/{token}">
                    <input type="text" name="pin" placeholder="••••" maxlength="6" pattern="[0-9]*" inputmode="numeric" required autofocus>
                    <br>
                    <button type="submit">Download</button>
                </form>
                <div class="footer">ShareCLI v2.0</div>
            </div>
        </body>
        </html>
        """
    
    @safe_handler
    def do_GET(self):
        client_ip = self.client_address[0]

        # Handle Share Link Access (NO AUTH REQUIRED)
        if self.path.startswith('/s/'):
            parts = self.path.split('?')[0].split('/')
            if len(parts) >= 3:
                token = parts[2]
                
                # Get PIN from query string if provided
                pin = None
                if '?' in self.path:
                    query_string = self.path.split('?')[1]
                    query_params = urllib.parse.parse_qs(query_string)
                    pin = query_params.get('pin', [None])[0]
                
                # Validate share link
                share_manager = get_share_manager()
                link_info = share_manager.validate_link(token, pin)
                
                if not link_info:
                    # Invalid or expired link
                    self.send_response(410)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(self._generate_error_page('Link Expired', 'This share link has expired or is no longer valid.').encode())
                    log_access(client_ip, f"/s/{token}", "🔗 EXPIRED LINK")
                    return
                
                if link_info.get('requires_pin'):
                    # Show PIN input page
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(self._generate_pin_page(token, link_info['file_name']).encode())
                    return
                
                if link_info.get('pin_invalid'):
                    # Invalid PIN - Show retry form with error message
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(self._generate_pin_page(token, link_info.get('file_name', 'File'), error=True).encode())
                    log_access(client_ip, f"/s/{token}", "🔒 WRONG PIN")
                    return
                
                # Valid link - serve file
                file_path = link_info['file_path']
                if os.path.exists(file_path) and os.path.isfile(file_path):
                    # Increment download counter
                    share_manager.increment_download(token)
                    
                    # Serve file
                    self.send_response(200)
                    file_size = os.path.getsize(file_path)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', f'attachment; filename=\"{link_info["file_name"]}\"')
                    self.send_header('Content-Length', str(file_size))
                    self.end_headers()
                    
                    with open(file_path, 'rb') as f:
                        self.wfile.write(f.read())
                    
                    log_access(client_ip, f"/s/{token} ({link_info['file_name']})", "🔗 SHARE DOWNLOAD")
                else:
                    self.send_response(404)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(self._generate_error_page('File Not Found', 'The shared file no longer exists.').encode())
                return
        
        # API Endpoint: List Share Links (REQUIRES AUTH)
        if self.path == '/api/share/list':
            # Check authentication
            auth_result = self.check_auth()
            
            if auth_result != 1:
                # Return JSON error instead of HTML redirect
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    'success': False,
                    'error': 'Authentication required'
                }).encode())
                log_access(client_ip, self.path, "🔒 AUTH FAILED")
                return
            
            # User is authenticated, return share links
            share_manager = get_share_manager()
            links = share_manager.list_active_links()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                'success': True,
                'links': links
            }
            self.wfile.write(json.dumps(response).encode())
            return
        

        # Handle Logout Action
        if self.path == '/logout':
            self.send_response(401)
            # TRICK: Change realm to force browser to drop credentials for the main realm
            self.send_header('WWW-Authenticate', 'Basic realm="ShareCLI - Logged Out"')
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            
            # Serve Logged Out Page
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Logged Out - ShareCLI</title>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    
                    body { 
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                        background-color: #050505;
                        color: #ffffff;
                        display: flex; 
                        align-items: center; 
                        justify-content: center; 
                        min-height: 100vh; 
                        margin: 0; 
                        text-align: center;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    /* Animated Background Mesh */
                    .bg-mesh {
                        position: fixed;
                        top: 0;
                        left: 0;
                        width: 100vw;
                        height: 100vh;
                        z-index: -1;
                        background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #050505 70%);
                    }
                    
                    .bg-mesh::before,
                    .bg-mesh::after {
                        content: '';
                        position: absolute;
                        width: 60vw;
                        height: 60vw;
                        border-radius: 50%;
                        filter: blur(100px);
                        opacity: 0.15;
                        animation: float 10s infinite alternate ease-in-out;
                    }
                    
                    .bg-mesh::before {
                        background: #3b82f6;
                        top: -10%;
                        left: -10%;
                    }
                    
                    .bg-mesh::after {
                        background: #8b5cf6;
                        bottom: -10%;
                        right: -10%;
                        animation-delay: -5s;
                    }
                    
                    @keyframes float {
                        0% { transform: translate(0, 0) scale(1); }
                        100% { transform: translate(20px, 40px) scale(1.1); }
                    }
                    
                    @keyframes fadeIn {
                        from { opacity: 0; transform: translateY(20px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
                    
                    .card { 
                        background: rgba(20, 20, 20, 0.6);
                        backdrop-filter: blur(20px);
                        padding: 3rem 2.5rem;
                        border-radius: 20px;
                        border: 1px solid rgba(255,255,255,0.1);
                        max-width: 90%;
                        width: 450px;
                        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                        animation: fadeIn 0.6s ease-out;
                        position: relative;
                        z-index: 1;
                    }
                    
                    .icon {
                        font-size: 4rem;
                        margin-bottom: 1.5rem;
                        filter: drop-shadow(0 0 20px rgba(16, 185, 129, 0.5));
                        animation: pulse 2s ease-in-out infinite;
                    }
                    
                    @keyframes pulse {
                        0%, 100% { opacity: 1; transform: scale(1); }
                        50% { opacity: 0.8; transform: scale(1.05); }
                    }
                    
                    h1 { 
                        margin-bottom: 1rem;
                        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        background-clip: text;
                        font-weight: 700;
                        font-size: 2rem;
                        letter-spacing: -0.02em;
                    }
                    
                    p { 
                        margin-bottom: 2.5rem;
                        color: #a1a1aa;
                        font-size: 1.05rem;
                        line-height: 1.6;
                    }
                    
                    button { 
                        color: #fff;
                        font-weight: 600;
                        font-family: 'Inter', sans-serif;
                        padding: 14px 32px;
                        background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                        border: none;
                        border-radius: 10px;
                        font-size: 16px;
                        cursor: pointer;
                        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                        box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
                        width: 100%;
                        max-width: 250px;
                    }
                    
                    button:hover { 
                        transform: translateY(-2px);
                        box-shadow: 0 6px 25px rgba(59, 130, 246, 0.5);
                        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
                    }
                    
                    button:active {
                        transform: translateY(0);
                    }
                    
                    .footer {
                        margin-top: 2rem;
                        font-size: 0.85rem;
                        color: #71717a;
                    }
                </style>
                <script>
                    function loginAgain() {
                        // Simple and fast: just redirect
                        window.location.href = '/';
                    }
                </script>
            </head>
            <body>
                <div class="bg-mesh"></div>
                <div class="card">
                    <div class="icon">✅</div>
                    <h1>Logged Out Successfully</h1>
                    <p>Your session has ended securely.<br>See you next time!</p>
                    <button onclick="loginAgain()">Login Again</button>
                    <div class="footer">ShareCLI v2.0</div>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
            log_access(client_ip, "Action", "🚪 LOGOUT")
            return
        
        # Security checks
        # 1. Check Auth First (Smart Rate Limit)
        auth_status = self.check_auth()
        
        if auth_status == 1:
            # Success: Unblock if needed
            with STATE_LOCK:
                if client_ip in BLOCKED_IPS:
                    del BLOCKED_IPS[client_ip]
                if client_ip in FAILED_ATTEMPTS:
                    FAILED_ATTEMPTS[client_ip] = 0
        else:
            # Not authenticated: Check Block
            if is_ip_blocked(client_ip):
                self.send_blocked_response()
                log_access(client_ip, self.path, "🚫 BLOCKED")
                return

            if auth_status == 0:
                # Wrong Password
                self.do_AUTHHEAD()
                
                AUTH_PAGE_HTML = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Authentication Failed - ShareCLI</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                            background-color: #050505;
                            color: #ffffff;
                            display: flex; 
                            align-items: center; 
                            justify-content: center; 
                            min-height: 100vh; 
                            margin: 0; 
                            text-align: center;
                            position: relative;
                            overflow: hidden;
                        }
                        
                        /* Animated Background Mesh */
                        .bg-mesh {
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            z-index: -1;
                            background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #050505 70%);
                        }
                        
                        .bg-mesh::before,
                        .bg-mesh::after {
                            content: '';
                            position: absolute;
                            width: 60vw;
                            height: 60vw;
                            border-radius: 50%;
                            filter: blur(100px);
                            opacity: 0.15;
                            animation: float 10s infinite alternate ease-in-out;
                        }
                        
                        .bg-mesh::before {
                            background: #3b82f6;
                            top: -10%;
                            left: -10%;
                        }
                        
                        .bg-mesh::after {
                            background: #8b5cf6;
                            bottom: -10%;
                            right: -10%;
                            animation-delay: -5s;
                        }
                        
                        @keyframes float {
                            0% { transform: translate(0, 0) scale(1); }
                            100% { transform: translate(20px, 40px) scale(1.1); }
                        }
                        
                        @keyframes fadeIn {
                            from { opacity: 0; transform: translateY(20px); }
                            to { opacity: 1; transform: translateY(0); }
                        }
                        
                        @keyframes shake {
                            0%, 100% { transform: translateX(0); }
                            10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
                            20%, 40%, 60%, 80% { transform: translateX(5px); }
                        }
                        
                        .card { 
                            background: rgba(20, 20, 20, 0.6);
                            backdrop-filter: blur(20px);
                            padding: 3rem 2.5rem;
                            border-radius: 20px;
                            border: 1px solid rgba(255,255,255,0.1);
                            max-width: 90%;
                            width: 450px;
                            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                            animation: fadeIn 0.6s ease-out, shake 0.5s ease-out;
                            position: relative;
                            z-index: 1;
                        }
                        
                        .icon {
                            font-size: 4rem;
                            margin-bottom: 1.5rem;
                            filter: drop-shadow(0 0 20px rgba(251, 191, 36, 0.5));
                        }
                        
                        h1 { 
                            margin-bottom: 1rem;
                            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
                            -webkit-background-clip: text;
                            -webkit-text-fill-color: transparent;
                            background-clip: text;
                            font-weight: 700;
                            font-size: 2rem;
                            letter-spacing: -0.02em;
                        }
                        
                        p { 
                            margin-bottom: 2.5rem;
                            color: #a1a1aa;
                            font-size: 1.05rem;
                            line-height: 1.6;
                        }
                        
                        button { 
                            color: #000;
                            font-weight: 600;
                            font-family: inherit;
                            padding: 14px 32px;
                            background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
                            border: none;
                            border-radius: 10px;
                            font-size: 16px;
                            cursor: pointer;
                            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                            box-shadow: 0 4px 15px rgba(251, 191, 36, 0.3);
                            width: 100%;
                            max-width: 250px;
                        }
                        
                        button:hover { 
                            transform: translateY(-2px);
                            box-shadow: 0 6px 25px rgba(251, 191, 36, 0.5);
                            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
                        }
                        
                        button:active {
                            transform: translateY(0);
                        }
                        
                        .footer {
                            margin-top: 2rem;
                            font-size: 0.85rem;
                            color: #71717a;
                        }
                    </style>
                </head>
                <body>
                    <div class="bg-mesh"></div>
                    <div class="card">
                        <div class="icon">🔒</div>
                        <h1>Authentication Failed</h1>
                        <p>Invalid credentials.<br>Please try again.</p>
                        <button onclick="location.reload()">Retry Login</button>
                        <div class="footer">ShareCLI v2.0</div>
                    </div>
                </body>
                </html>
                """
                self.wfile.write(AUTH_PAGE_HTML.encode('utf-8'))
                record_failed_attempt(client_ip)
                log_access(client_ip, self.path, "🔒 AUTH FAILED")
                return
            
            elif auth_status == 2:
                # No Header (First visit)
                self.do_AUTHHEAD()
                
                AUTH_PAGE_HTML = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Authentication Required - ShareCLI</title>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    <style>
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                            background-color: #050505;
                            color: #ffffff;
                            display: flex; 
                            align-items: center; 
                            justify-content: center; 
                            min-height: 100vh; 
                            margin: 0; 
                            text-align: center;
                            position: relative;
                            overflow: hidden;
                        }
                        
                        /* Animated Background Mesh */
                        .bg-mesh {
                            position: fixed;
                            top: 0;
                            left: 0;
                            width: 100vw;
                            height: 100vh;
                            z-index: -1;
                            background: radial-gradient(circle at 50% 0%, #1e1b4b 0%, #050505 70%);
                        }
                        
                        .bg-mesh::before,
                        .bg-mesh::after {
                            content: '';
                            position: absolute;
                            width: 60vw;
                            height: 60vw;
                            border-radius: 50%;
                            filter: blur(100px);
                            opacity: 0.15;
                            animation: float 10s infinite alternate ease-in-out;
                        }
                        
                        .bg-mesh::before {
                            background: #3b82f6;
                            top: -10%;
                            left: -10%;
                        }
                        
                        .bg-mesh::after {
                            background: #8b5cf6;
                            bottom: -10%;
                            right: -10%;
                            animation-delay: -5s;
                        }
                        
                        @keyframes float {
                            0% { transform: translate(0, 0) scale(1); }
                            100% { transform: translate(20px, 40px) scale(1.1); }
                        }
                        
                        @keyframes fadeIn {
                            from { opacity: 0; transform: translateY(20px); }
                            to { opacity: 1; transform: translateY(0); }
                        }
                        
                        .card { 
                            background: rgba(20, 20, 20, 0.6);
                            backdrop-filter: blur(20px);
                            padding: 3rem 2.5rem;
                            border-radius: 20px;
                            border: 1px solid rgba(255,255,255,0.1);
                            max-width: 90%;
                            width: 450px;
                            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                            animation: fadeIn 0.6s ease-out;
                            position: relative;
                            z-index: 1;
                        }
                        
                        .icon {
                            font-size: 4rem;
                            margin-bottom: 1.5rem;
                            filter: drop-shadow(0 0 20px rgba(59, 130, 246, 0.5));
                            animation: pulse 2s ease-in-out infinite;
                        }
                        
                        @keyframes pulse {
                            0%, 100% { opacity: 1; transform: scale(1); }
                            50% { opacity: 0.8; transform: scale(1.05); }
                        }
                        
                        h1 { 
                            margin-bottom: 1rem;
                            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                            -webkit-background-clip: text;
                            -webkit-text-fill-color: transparent;
                            background-clip: text;
                            font-weight: 700;
                            font-size: 2rem;
                            letter-spacing: -0.02em;
                        }
                        
                        p { 
                            margin-bottom: 2.5rem;
                            color: #a1a1aa;
                            font-size: 1.05rem;
                            line-height: 1.6;
                        }
                        
                        button { 
                            color: #fff;
                            font-weight: 600;
                            font-family: inherit;
                            padding: 14px 32px;
                            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
                            border: none;
                            border-radius: 10px;
                            font-size: 16px;
                            cursor: pointer;
                            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
                            width: 100%;
                            max-width: 250px;
                        }
                        
                        button:hover { 
                            transform: translateY(-2px);
                            box-shadow: 0 6px 25px rgba(59, 130, 246, 0.5);
                            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
                        }
                        
                        button:active {
                            transform: translateY(0);
                        }
                        
                        .footer {
                            margin-top: 2rem;
                            font-size: 0.85rem;
                            color: #71717a;
                        }
                    </style>
                </head>
                <body>
                    <div class="bg-mesh"></div>
                    <div class="card">
                        <div class="icon">🔐</div>
                        <h1>Secure Access Required</h1>
                        <p>This server requires authentication.<br>Please log in to continue.</p>
                        <button onclick="location.reload()">Login</button>
                        <div class="footer">ShareCLI v2.0</div>
                    </div>
                </body>
                </html>
                """
                self.wfile.write(AUTH_PAGE_HTML.encode('utf-8'))
                # No penalty for missing credentials
                return
        
        # 2. Whitelist Check
        if not is_ip_whitelisted(client_ip):
            self.send_whitelist_denied()
            log_access(client_ip, self.path, "⛔ NOT WHITELISTED")
            return
        
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
                log_access(client_ip, f"📦 {folder_name}.zip", "✅ ZIP DOWNLOAD")
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
                log_access(client_ip, path, "📂 BROWSE")
                return
        
        # Serve file normally
        log_access(client_ip, self.path, "⬇️ DOWNLOAD")
        super().do_GET()
    
    def do_HEAD(self):
        client_ip = self.client_address[0]
        if is_ip_blocked(client_ip) or not is_ip_whitelisted(client_ip):
            return
        if not self.check_auth():
            self.do_AUTHHEAD()
            return
        super().do_HEAD()

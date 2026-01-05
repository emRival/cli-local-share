"""
SFTP Server Module for ShareCLI
Uses sftpserver library (based on paramiko)
"""

import os
import threading
import logging
import socket
from typing import Optional

# Suppress logging
logging.getLogger('paramiko').setLevel(logging.WARNING)

SFTP_SOCKET = None
SFTP_THREAD = None
SFTP_RUNNING = False


def is_sftp_available() -> bool:
    """Check if sftpserver/paramiko is installed."""
    try:
        import paramiko
        from sftpserver.stub_sftp import StubSFTPServer
        return True
    except ImportError:
        return False


def _get_host_key():
    """Get or generate SSH host key."""
    import paramiko
    key_file = '/tmp/sharecli_host_key'
    
    if os.path.exists(key_file):
        try:
            return paramiko.RSAKey(filename=key_file)
        except:
            pass
    
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(key_file)
    return key


def _create_sftp_server_class(root_dir: str, allow_write: bool):
    """Create a custom SFTPServer class with the specified root directory."""
    from paramiko import SFTPServerInterface, SFTPServer, SFTPAttributes, SFTPHandle, SFTP_OK
    
    class CustomSFTPHandle(SFTPHandle):
        def stat(self):
            try:
                return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def chattr(self, attr):
            try:
                SFTPServer.set_file_attr(self.filename, attr)
                return SFTP_OK
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
    
    class CustomSFTPServer(SFTPServerInterface):
        ROOT = os.path.abspath(root_dir)
        ALLOW_WRITE = allow_write
        
        def _realpath(self, path):
            # Handle empty or relative paths
            if not path or path == '.':
                return self.ROOT
            
            # Normalize the path
            normalized = self.canonicalize(path)
            real = os.path.normpath(self.ROOT + normalized)
            
            # Prevent directory traversal
            if not real.startswith(self.ROOT):
                return self.ROOT
            return real
        
        def list_folder(self, path):
            path = self._realpath(path)
            try:
                out = []
                for fname in os.listdir(path):
                    fpath = os.path.join(path, fname)
                    try:
                        attr = SFTPAttributes.from_stat(os.stat(fpath))
                        attr.filename = fname
                        out.append(attr)
                    except OSError:
                        pass
                return out
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def stat(self, path):
            path = self._realpath(path)
            try:
                return SFTPAttributes.from_stat(os.stat(path))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def lstat(self, path):
            path = self._realpath(path)
            try:
                return SFTPAttributes.from_stat(os.lstat(path))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def open(self, path, flags, attr):
            import paramiko
            # Check write permission
            write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
            if (flags & write_flags) and not self.ALLOW_WRITE:
                return paramiko.SFTP_PERMISSION_DENIED
            
            path = self._realpath(path)
            try:
                binary_flag = getattr(os, 'O_BINARY', 0)
                flags |= binary_flag
                mode = getattr(attr, 'st_mode', None)
                if mode is not None:
                    fd = os.open(path, flags, mode)
                else:
                    fd = os.open(path, flags, 0o666)
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            
            if (flags & os.O_CREAT) and (attr is not None):
                attr._flags &= ~attr.FLAG_PERMISSIONS
                SFTPServer.set_file_attr(path, attr)
            
            if flags & os.O_WRONLY:
                fstr = 'ab' if (flags & os.O_APPEND) else 'wb'
            elif flags & os.O_RDWR:
                fstr = 'a+b' if (flags & os.O_APPEND) else 'r+b'
            else:
                fstr = 'rb'
            
            try:
                f = os.fdopen(fd, fstr)
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            
            fobj = CustomSFTPHandle(flags)
            fobj.filename = path
            fobj.readfile = f
            fobj.writefile = f
            return fobj
        
        def remove(self, path):
            import paramiko
            if not self.ALLOW_WRITE:
                return paramiko.SFTP_PERMISSION_DENIED
            path = self._realpath(path)
            try:
                os.remove(path)
                return SFTP_OK
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def rename(self, oldpath, newpath):
            import paramiko
            if not self.ALLOW_WRITE:
                return paramiko.SFTP_PERMISSION_DENIED
            oldpath = self._realpath(oldpath)
            newpath = self._realpath(newpath)
            try:
                os.rename(oldpath, newpath)
                return SFTP_OK
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def mkdir(self, path, attr):
            import paramiko
            if not self.ALLOW_WRITE:
                return paramiko.SFTP_PERMISSION_DENIED
            path = self._realpath(path)
            try:
                os.mkdir(path)
                if attr is not None:
                    SFTPServer.set_file_attr(path, attr)
                return SFTP_OK
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def rmdir(self, path):
            import paramiko
            if not self.ALLOW_WRITE:
                return paramiko.SFTP_PERMISSION_DENIED
            path = self._realpath(path)
            try:
                os.rmdir(path)
                return SFTP_OK
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def canonicalize(self, path):
            if not path:
                return '/'
            if path == '.':
                return '/'
            if not path.startswith('/'):
                path = '/' + path
            return os.path.normpath(path)
    
    return CustomSFTPServer


def _create_auth_server_class(username: str, password: str):
    """Create a custom SSH server class with authentication."""
    from paramiko import ServerInterface, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED
    
    class CustomAuthServer(ServerInterface):
        def check_auth_password(self, u, p):
            if u == username and p == password:
                return AUTH_SUCCESSFUL
            return AUTH_FAILED
        
        def check_auth_publickey(self, username, key):
            return AUTH_FAILED  # Only password auth
        
        def check_channel_request(self, kind, chanid):
            if kind == 'session':
                return OPEN_SUCCEEDED
            return AUTH_FAILED
        
        def get_allowed_auths(self, username):
            return "password"
    
    return CustomAuthServer


def _handle_client(client, addr, host_key, username, password, root_dir, allow_write):
    """Handle a single SFTP connection."""
    import src.security as security
    
    transport = None
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        
        # Log connection attempt
        ip = addr[0]
        security.log_access(ip, "/", "SFTP Connect")
        
        # Create custom SFTP server class with logging
        sftp_base_class = _create_sftp_server_class(root_dir, allow_write)
        
        class LoggingSFTPServer(sftp_base_class):
            def open(self, path, flags, attr):
                # Log file access
                try:
                    security.log_access(ip, path, "SFTP Open")
                except:
                    pass
                return super().open(path, flags, attr)
                
        transport.set_subsystem_handler('sftp', paramiko.SFTPServer, LoggingSFTPServer)
        
        # Start SSH server with custom auth
        auth_class = _create_auth_server_class(username, password)
        server = auth_class()
        transport.start_server(server=server)
        
        # Wait for client
        channel = transport.accept(60)
        if channel is None:
            return
        
        # Keep alive until disconnect
        while transport.is_active():
            import time
            time.sleep(1)
            
    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except:
                pass


def create_sftp_server(
    directory: str,
    port: int = 2222,
    username: str = "user",
    password: str = "",
    allow_write: bool = False
) -> Optional[socket.socket]:
    """Create SFTP server socket."""
    if not is_sftp_available():
        return None
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        sock.settimeout(1)
        return sock
    except OSError:
        return None


def start_sftp_server(
    sock: socket.socket,
    username: str,
    password: str,
    directory: str,
    allow_write: bool
) -> bool:
    """Start SFTP server in background."""
    global SFTP_SOCKET, SFTP_THREAD, SFTP_RUNNING
    
    if sock is None:
        return False
    
    SFTP_SOCKET = sock
    SFTP_RUNNING = True
    host_key = _get_host_key()
    
    def serve():
        global SFTP_RUNNING
        while SFTP_RUNNING:
            try:
                client, addr = sock.accept()
                t = threading.Thread(
                    target=_handle_client,
                    args=(client, addr, host_key, username, password, directory, allow_write),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break
    
    SFTP_THREAD = threading.Thread(target=serve, daemon=True)
    SFTP_THREAD.start()
    return True


def stop_sftp_server():
    """Stop SFTP server."""
    global SFTP_SOCKET, SFTP_THREAD, SFTP_RUNNING
    
    SFTP_RUNNING = False
    
    if SFTP_SOCKET:
        try:
            SFTP_SOCKET.close()
        except:
            pass
        SFTP_SOCKET = None
    
    SFTP_THREAD = None

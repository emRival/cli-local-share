import os
import ssl
import subprocess
import socket
import ipaddress
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm

from src.state import ACCESS_LOG, BLOCKED_IPS, FAILED_ATTEMPTS, WHITELIST_IPS, MAX_FAILED_ATTEMPTS, BLOCK_DURATION_SECONDS, STATE_LOCK
from src.utils import get_local_ip, get_network_range

console = Console()

def log_access(ip: str, path: str, status: str):
    """Log access to the server"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Memory log
    with STATE_LOCK:
        ACCESS_LOG.append({
            "time": timestamp.split(" ")[1], # Just time for UI
            "ip": ip,
            "path": path,
            "status": status
        })
        if len(ACCESS_LOG) > 30:
            # Keep last 30 logs in UI
            del ACCESS_LOG[:-30]
        
    # File log (Persistence)
    try:
        with open("access.log", "a") as f:
            f.write(f"[{timestamp}] IP: {ip} | Status: {status} | Path: {path}\n")
    except:
        pass


def is_ip_blocked(ip: str) -> bool:
    """Check if IP is blocked"""
    with STATE_LOCK:
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
    with STATE_LOCK:
        FAILED_ATTEMPTS[ip] += 1
        
        if FAILED_ATTEMPTS[ip] >= MAX_FAILED_ATTEMPTS:
            BLOCKED_IPS[ip] = datetime.now() + timedelta(seconds=BLOCK_DURATION_SECONDS)
            # Release lock before calling log_access to avoid potential deadlock if log_access also locks (it does!)
            # But wait, log_access locks independently. It's safe if re-entrant or fine-grained. 
            # Re-entrant lock would be better, but default Lock isn't.
            # Best to just log after releasing, or accept that log_access uses lock too.
            # Since log_access is short and simple, we can call it outside or inside if we are careful.
            # Actually, log_access is self-contained. better call it outside this lock if possible, 
            # OR make log_access robust. 
            # Given log_access acquires lock, calling it inside another lock will DEADLOCK.
            should_log_block = True
        else:
            should_log_block = False

    if should_log_block:
        log_access(ip, "-", f"🚫 BLOCKED ({BLOCK_DURATION_SECONDS}s)")


def is_ip_whitelisted(ip: str) -> bool:
    """Check if IP is in whitelist (empty whitelist = allow all)"""
    with STATE_LOCK:
        if not WHITELIST_IPS:
            return True
        return ip in WHITELIST_IPS or ip == "127.0.0.1"


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


def setup_whitelist():
    """Interactive whitelist setup"""
    
    console.print("\n[bold cyan]🛡️ IP WHITELIST SETUP[/bold cyan]\n")
    
    use_whitelist = Confirm.ask("Aktifkan IP Whitelist?", default=False)
    
    if not use_whitelist:
        WHITELIST_IPS.clear()
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
            
            selection = Prompt.ask("Pilihan", default="none")
            
            if selection.lower() == 'all':
                for host in hosts:
                    WHITELIST_IPS.add(host["ip"])
            elif selection.lower() != 'none':
                try:
                    indices = [int(x.strip()) for x in selection.split(',')]
                    for idx in indices:
                        if 1 <= idx <= len(hosts):
                            ip = hosts[idx-1]["ip"]
                            WHITELIST_IPS.add(ip)
                            console.print(f"[green]✓ Whitelisted: {ip}[/green]")
                except:
                    console.print("[red]Invalid selection[/red]") 

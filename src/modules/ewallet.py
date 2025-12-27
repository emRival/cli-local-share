"""
E-Wallet Name Checker Module - Scam Check v2

Note: This module provides a simulation/demo of e-wallet checking.
Real implementation would require official API access from each provider.
"""
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import Optional

from .utils import normalize_phone, validate_indonesian_phone

console = Console()

# Supported e-wallets (for display purposes)
SUPPORTED_EWALLETS = [
    {"name": "GoPay", "icon": "🟢", "status": "Demo Mode"},
    {"name": "OVO", "icon": "🟣", "status": "Demo Mode"},
    {"name": "DANA", "icon": "🔵", "status": "Demo Mode"},
    {"name": "ShopeePay", "icon": "🟠", "status": "Demo Mode"},
    {"name": "LinkAja", "icon": "🔴", "status": "Demo Mode"},
]


def check_ewallet(phone: str) -> dict:
    """
    Check e-wallet information for a phone number
    
    Note: This is a demo/simulation. Real implementation would require
    official API access from each e-wallet provider.
    """
    normalized = normalize_phone(phone)
    
    if not validate_indonesian_phone(normalized):
        return {"valid": False, "error": "Nomor tidak valid"}
    
    # Demo response - in real implementation, this would call actual APIs
    result = {
        "valid": True,
        "phone": normalized,
        "ewallets": []
    }
    
    for wallet in SUPPORTED_EWALLETS:
        result["ewallets"].append({
            "name": wallet["name"],
            "icon": wallet["icon"],
            "registered": None,  # Unknown - would need API
            "status": wallet["status"],
            "message": "Memerlukan API resmi untuk cek registrasi"
        })
    
    return result


def display_ewallet_result(result: dict):
    """Display e-wallet check result"""
    if not result.get("valid"):
        console.print(Panel(
            f"[red]❌ {result.get('error', 'Error')}[/red]",
            title="E-Wallet Check",
            border_style="red"
        ))
        return
    
    console.print(f"\n[bold]Nomor: [cyan]{result['phone']}[/cyan][/bold]\n")
    
    table = Table(title="Status E-Wallet", show_header=True, header_style="bold cyan")
    table.add_column("E-Wallet", style="white", width=15)
    table.add_column("Status", style="yellow", width=15)
    table.add_column("Keterangan", style="dim", width=40)
    
    for wallet in result["ewallets"]:
        table.add_row(
            f"{wallet['icon']} {wallet['name']}",
            wallet["status"],
            wallet["message"]
        )
    
    console.print(table)
    
    console.print(Panel(
        "[yellow]⚠️ Fitur ini dalam mode demo.\n"
        "Untuk cek nama e-wallet yang sebenarnya, diperlukan:\n"
        "• API resmi dari masing-masing provider\n"
        "• Atau transfer nominal kecil (Rp1) untuk verifikasi nama[/yellow]",
        title="Catatan",
        border_style="yellow"
    ))


def ewallet_check_interactive():
    """Interactive e-wallet check"""
    console.print("\n[bold cyan]💳 E-WALLET CHECKER[/bold cyan]\n")
    
    # Show supported e-wallets
    console.print("[dim]E-Wallet yang didukung:[/dim]")
    for wallet in SUPPORTED_EWALLETS:
        console.print(f"  {wallet['icon']} {wallet['name']}")
    console.print()
    
    phone = console.input("[yellow]Masukkan nomor HP: [/yellow]")
    
    if not phone.strip():
        console.print("[red]Nomor tidak boleh kosong![/red]")
        return
    
    console.print("\n[dim]Memeriksa e-wallet...[/dim]\n")
    
    result = check_ewallet(phone.strip())
    display_ewallet_result(result)
    
    console.input("\n[dim]Tekan Enter untuk kembali...[/dim]")

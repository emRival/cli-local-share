"""
Menu Module - Scam Check v2
"""
import questionary
from rich.console import Console
from rich.panel import Panel

from .modules.utils import print_banner
from .modules.phone_lookup import phone_lookup_interactive
from .modules.ewallet import ewallet_check_interactive

console = Console()


def show_menu():
    """Display main menu and handle selection"""
    choices = [
        questionary.Choice("📱 Phone Lookup - Cek informasi nomor HP", value="phone"),
        questionary.Choice("💳 E-Wallet Check - Cek nama e-wallet", value="ewallet"),
        questionary.Choice("ℹ️  About - Tentang aplikasi", value="about"),
        questionary.Choice("🚪 Exit - Keluar", value="exit"),
    ]
    
    return questionary.select(
        "Pilih menu:",
        choices=choices,
        style=questionary.Style([
            ('qmark', 'fg:cyan bold'),
            ('question', 'fg:white bold'),
            ('pointer', 'fg:cyan bold'),
            ('highlighted', 'fg:cyan bold'),
            ('selected', 'fg:green'),
        ])
    ).ask()


def show_about():
    """Show about information"""
    about_text = """
[bold cyan]Scam Check v2.0.0[/bold cyan]

[white]OSINT Phone Lookup Tool untuk membantu verifikasi nomor 
sebelum melakukan transaksi online.[/white]

[bold]Fitur:[/bold]
  📱 Phone Lookup - Informasi carrier, lokasi, format nomor
  💳 E-Wallet Check - Cek registrasi e-wallet (demo mode)

[bold]Disclaimer:[/bold]
  [yellow]Tool ini hanya untuk tujuan edukasi dan verifikasi.
  Gunakan dengan bijak dan bertanggung jawab.[/yellow]

[dim]GitHub: github.com/emRival/scam-check[/dim]
"""
    console.print(Panel(about_text, title="About", border_style="cyan"))
    console.input("\n[dim]Tekan Enter untuk kembali...[/dim]")


def main_loop():
    """Main application loop"""
    while True:
        console.clear()
        print_banner()
        
        choice = show_menu()
        
        if choice == "phone":
            phone_lookup_interactive()
        elif choice == "ewallet":
            ewallet_check_interactive()
        elif choice == "about":
            show_about()
        elif choice == "exit" or choice is None:
            console.print("\n[cyan]👋 Terima kasih telah menggunakan Scam Check![/cyan]\n")
            break

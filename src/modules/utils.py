"""
Utility functions for Scam Check v2
"""
import re
from typing import Optional
from rich.console import Console

console = Console()

# Indonesian carrier prefixes
CARRIER_PREFIXES = {
    # Telkomsel
    "0811": "Telkomsel (Halo)",
    "0812": "Telkomsel (simPATI)",
    "0813": "Telkomsel (simPATI)",
    "0821": "Telkomsel (simPATI)",
    "0822": "Telkomsel (simPATI/Loop)",
    "0823": "Telkomsel (AS)",
    "0851": "Telkomsel (AS)",
    "0852": "Telkomsel (AS)",
    "0853": "Telkomsel (AS)",
    
    # Indosat Ooredoo
    "0814": "Indosat (Matrix)",
    "0815": "Indosat (Matrix)",
    "0816": "Indosat (Matrix)",
    "0855": "Indosat (IM3)",
    "0856": "Indosat (IM3)",
    "0857": "Indosat (IM3)",
    "0858": "Indosat (Mentari)",
    
    # XL Axiata
    "0817": "XL Axiata",
    "0818": "XL Axiata",
    "0819": "XL Axiata",
    "0859": "XL Axiata",
    "0877": "XL Axiata",
    "0878": "XL Axiata",
    "0879": "XL Axiata",
    
    # Axis
    "0831": "Axis",
    "0832": "Axis",
    "0833": "Axis",
    "0838": "Axis",
    
    # Three (3)
    "0895": "Three (Tri)",
    "0896": "Three (Tri)",
    "0897": "Three (Tri)",
    "0898": "Three (Tri)",
    "0899": "Three (Tri)",
    
    # Smartfren
    "0881": "Smartfren",
    "0882": "Smartfren",
    "0883": "Smartfren",
    "0884": "Smartfren",
    "0885": "Smartfren",
    "0886": "Smartfren",
    "0887": "Smartfren",
    "0888": "Smartfren",
    "0889": "Smartfren",
    
    # By.U (Telkomsel Digital)
    "0851": "By.U (Telkomsel)",
}


def normalize_phone(phone: str) -> str:
    """Normalize phone number to Indonesian format (08xxx)"""
    # Remove all non-digits
    phone = re.sub(r'\D', '', phone)
    
    # Handle +62
    if phone.startswith('62'):
        phone = '0' + phone[2:]
    
    # Handle 8xxx (without leading 0)
    if phone.startswith('8') and len(phone) >= 10:
        phone = '0' + phone
    
    return phone


def validate_indonesian_phone(phone: str) -> bool:
    """Validate if phone number is valid Indonesian mobile number"""
    phone = normalize_phone(phone)
    
    # Indonesian mobile numbers: 10-13 digits starting with 08
    if not re.match(r'^08\d{8,11}$', phone):
        return False
    
    return True


def get_carrier(phone: str) -> Optional[str]:
    """Get carrier name from phone number prefix"""
    phone = normalize_phone(phone)
    
    if len(phone) < 4:
        return None
    
    prefix = phone[:4]
    return CARRIER_PREFIXES.get(prefix, "Unknown Carrier")


def format_phone_display(phone: str) -> dict:
    """Format phone number for display"""
    normalized = normalize_phone(phone)
    
    return {
        "original": phone,
        "normalized": normalized,
        "international": f"+62{normalized[1:]}" if normalized.startswith('0') else phone,
        "local": normalized,
    }


def print_banner():
    """Print application banner"""
    banner = """
[bold cyan]╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   [bold white]███████╗ ██████╗ █████╗ ███╗   ███╗[/bold white]                          ║
║   [bold white]██╔════╝██╔════╝██╔══██╗████╗ ████║[/bold white]                          ║
║   [bold white]███████╗██║     ███████║██╔████╔██║[/bold white]                          ║
║   [bold white]╚════██║██║     ██╔══██║██║╚██╔╝██║[/bold white]                          ║
║   [bold white]███████║╚██████╗██║  ██║██║ ╚═╝ ██║[/bold white]                          ║
║   [bold white]╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝[/bold white]                          ║
║                                                               ║
║   [bold green]CHECK[/bold green] - OSINT Phone Lookup Tool                           ║
║   [dim]Version 2.0.0 | github.com/emRival/scam-check[/dim]              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝[/bold cyan]
"""
    console.print(banner)

"""
Phone Lookup Module - Scam Check v2
"""
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import Optional

from .utils import (
    normalize_phone, 
    validate_indonesian_phone, 
    get_carrier as get_local_carrier,
    format_phone_display
)

console = Console()


def lookup_phone(phone: str) -> Optional[dict]:
    """
    Perform comprehensive phone number lookup
    """
    # Normalize the phone number
    normalized = normalize_phone(phone)
    
    if not validate_indonesian_phone(normalized):
        return None
    
    # Parse with phonenumbers library
    try:
        # Parse as Indonesian number
        parsed = phonenumbers.parse(normalized, "ID")
        
        if not phonenumbers.is_valid_number(parsed):
            return None
        
        # Get information
        result = {
            "valid": True,
            "number": {
                "original": phone,
                "normalized": normalized,
                "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            },
            "carrier": {
                "name": carrier.name_for_number(parsed, "id") or get_local_carrier(normalized),
                "local_detection": get_local_carrier(normalized),
            },
            "location": {
                "country": "Indonesia",
                "country_code": "+62",
                "region": geocoder.description_for_number(parsed, "id") or "Indonesia",
            },
            "timezone": list(timezone.time_zones_for_number(parsed)),
            "type": _get_number_type(parsed),
        }
        
        return result
        
    except Exception as e:
        console.print(f"[red]Error parsing number: {e}[/red]")
        return None


def _get_number_type(parsed) -> str:
    """Get the type of phone number"""
    number_type = phonenumbers.number_type(parsed)
    
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE: "Mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
        phonenumbers.PhoneNumberType.VOIP: "VoIP",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        phonenumbers.PhoneNumberType.PAGER: "Pager",
        phonenumbers.PhoneNumberType.UAN: "UAN",
        phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
        phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
    }
    
    return type_map.get(number_type, "Unknown")


def display_lookup_result(result: dict):
    """Display lookup result in a nice format"""
    if not result:
        console.print(Panel(
            "[red]❌ Nomor tidak valid atau tidak ditemukan[/red]",
            title="Hasil Lookup",
            border_style="red"
        ))
        return
    
    # Create main info table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="white")
    
    # Number formats
    table.add_row("📱 Nomor Asli", result["number"]["original"])
    table.add_row("📞 Format E164", result["number"]["e164"])
    table.add_row("🌍 International", result["number"]["international"])
    table.add_row("🏠 National", result["number"]["national"])
    table.add_row("", "")
    
    # Carrier info
    carrier_name = result["carrier"]["name"] or result["carrier"]["local_detection"]
    table.add_row("📡 Operator", carrier_name or "Unknown")
    table.add_row("", "")
    
    # Location
    table.add_row("🌏 Negara", result["location"]["country"])
    table.add_row("📍 Region", result["location"]["region"])
    table.add_row("🕐 Timezone", ", ".join(result["timezone"]) if result["timezone"] else "Asia/Jakarta")
    table.add_row("", "")
    
    # Type
    table.add_row("📋 Tipe Nomor", result["type"])
    
    # Display in panel
    console.print(Panel(
        table,
        title="[bold green]✅ Hasil Lookup Nomor[/bold green]",
        border_style="green",
        padding=(1, 2)
    ))


def phone_lookup_interactive():
    """Interactive phone lookup"""
    console.print("\n[bold cyan]📱 PHONE LOOKUP[/bold cyan]\n")
    
    phone = console.input("[yellow]Masukkan nomor HP (contoh: 081234567890): [/yellow]")
    
    if not phone.strip():
        console.print("[red]Nomor tidak boleh kosong![/red]")
        return
    
    console.print("\n[dim]Mencari informasi...[/dim]\n")
    
    result = lookup_phone(phone.strip())
    display_lookup_result(result)
    
    console.input("\n[dim]Tekan Enter untuk kembali...[/dim]")

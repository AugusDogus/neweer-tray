"""Find the Neewer dongle - check serial ports and analyze the database."""

import sqlite3
from pathlib import Path

import serial.tools.list_ports


NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")
DB_PATH = NEEWER_DIR / "sqlnw24g.db"


def list_serial_ports() -> None:
    """List all available serial/COM ports."""
    print("Serial/COM Ports:")
    print("=" * 80)
    
    ports = serial.tools.list_ports.comports()
    
    if not ports:
        print("  No serial ports found")
        return
    
    for port in ports:
        print(f"  Port: {port.device}")
        print(f"    Description: {port.description}")
        print(f"    HWID: {port.hwid}")
        print(f"    VID:PID: {port.vid:04X}:{port.pid:04X}" if port.vid else "    VID:PID: N/A")
        print(f"    Serial Number: {port.serial_number}")
        print(f"    Manufacturer: {port.manufacturer}")
        print(f"    Product: {port.product}")
        print()


def analyze_database() -> None:
    """Analyze the Neewer SQLite database for device info."""
    print("\nNeewer Database Analysis:")
    print("=" * 80)
    
    if not DB_PATH.exists():
        print(f"  Database not found: {DB_PATH}")
        return
    
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"  Tables: {[t[0] for t in tables]}")
        
        # Examine each table
        for (table_name,) in tables:
            print(f"\n  Table: {table_name}")
            print("  " + "-" * 40)
            
            # Get column info
            cursor.execute(f"PRAGMA table_info({table_name});")
            columns = cursor.fetchall()
            col_names = [col[1] for col in columns]
            print(f"    Columns: {col_names}")
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
            count = cursor.fetchone()[0]
            print(f"    Row count: {count}")
            
            # Show sample data (first 5 rows)
            if count > 0:
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 5;")
                rows = cursor.fetchall()
                print("    Sample data:")
                for row in rows:
                    print(f"      {row}")
        
        conn.close()
    except Exception as e:
        print(f"  Error: {e}")


def check_windows_devices() -> None:
    """Check for Neewer in Windows device list via WMI."""
    print("\nWindows Device Check (looking for Neewer/CH341):")
    print("=" * 80)
    
    try:
        import subprocess
        result = subprocess.run(
            ['powershell.exe', '-NoProfile', '-Command',
             "Get-PnpDevice | Where-Object { $_.FriendlyName -like '*CH341*' -or $_.FriendlyName -like '*Neewer*' -or $_.Description -like '*CH341*' } | Select-Object FriendlyName, InstanceId, Status | Format-List"],
            capture_output=True, text=True
        )
        if result.stdout.strip():
            print(result.stdout)
        else:
            print("  No CH341 or Neewer devices found in PnP devices")
    except Exception as e:
        print(f"  Error: {e}")


def main() -> None:
    print("Neewer Device Discovery")
    print("=" * 80)
    
    list_serial_ports()
    analyze_database()
    check_windows_devices()


if __name__ == "__main__":
    main()


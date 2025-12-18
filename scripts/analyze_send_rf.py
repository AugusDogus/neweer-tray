"""Analyze the Send_RF_DATA function signature and try to send commands."""

import ctypes
from ctypes import wintypes
from pathlib import Path
import struct


NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")
DLL_PATH = NEEWER_DIR / "Set_Dongle_RF_API_x64.dll"


def load_dll() -> ctypes.CDLL:
    """Load the Neewer RF API DLL."""
    return ctypes.CDLL(str(DLL_PATH))


def test_send_signatures(dll: ctypes.CDLL) -> None:
    """Try different function signatures for Send_RF_DATA."""
    print("Testing Send_RF_DATA signatures")
    print("=" * 80)
    
    send_rf_data = dll.Send_RF_DATA
    
    # Common patterns for RF send functions:
    # 1. int Send_RF_DATA(unsigned char* data, int length)
    # 2. int Send_RF_DATA(int channel, unsigned char* data, int length)  
    # 3. int Send_RF_DATA(unsigned char* data, int length, int timeout)
    # 4. int Send_RF_DATA(void* handle, unsigned char* data, int length)
    
    # Based on the database schema, commands likely include:
    # - Channel (0-307)
    # - Brightness (0-100)
    # - CCT (color temperature)
    # - RGB values
    # - On/Off state
    
    # Let's try a simple test with a safe-looking signature
    # First, let's see what happens with just checking the function exists
    
    print(f"Send_RF_DATA function address: {ctypes.cast(send_rf_data, ctypes.c_void_p).value:#x}")
    
    # Try signature: int Send_RF_DATA(unsigned char* data, int length)
    print("\nTrying signature: int Send_RF_DATA(unsigned char* data, int length)")
    send_rf_data.restype = ctypes.c_int
    send_rf_data.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    
    # Create a test buffer - let's NOT send anything yet, just prepare
    # Typical RF command might be something like:
    # [header, channel, command, value1, value2, ..., checksum]
    
    # Based on similar RF protocols, a turn-on command might look like:
    # Channel 0, Turn On: [0x78, 0x00, 0x01, 0x00, 0x00, ...]  (guessing)
    
    print("\n*** NOT SENDING YET - Need to capture actual protocol first ***")
    print("We should use Wireshark/USBPcap or API Monitor to see real commands")


def examine_database_for_clues() -> None:
    """Look at database for protocol hints."""
    import sqlite3
    
    print("\n\nDatabase Protocol Hints")
    print("=" * 80)
    
    db_path = NEEWER_DIR / "sqlnw24g.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Look at scene data which might reveal command structure
    cursor.execute("""
        SELECT DISTINCT SceneName, chChannel, chBright, chCCT, chHsi, chEffect 
        FROM nw_24gscene 
        LIMIT 20
    """)
    
    print("Scene configurations (hints at command parameters):")
    for row in cursor.fetchall():
        print(f"  Scene: {row[0]}, Channel: {row[1]}, Bright: {row[2]}, CCT: {row[3]}, HSI: {row[4]}, Effect: {row[5]}")
    
    # Look at device configurations
    cursor.execute("""
        SELECT id, deviceName, chChannel, chCCTBright, chLight, chAccessOnOff
        FROM nw_24gdevice 
        WHERE chChannel < 10
        LIMIT 10
    """)
    
    print("\nDevice configurations:")
    for row in cursor.fetchall():
        print(f"  ID: {row[0]}, Name: {row[1]}, Channel: {row[2]}, Bright: {row[3]}, Light: {row[4]}, OnOff: {row[5]}")
    
    conn.close()


def suggest_next_steps() -> None:
    """Suggest next steps for reverse engineering."""
    print("\n\nNext Steps for Reverse Engineering")
    print("=" * 80)
    print("""
To capture the actual protocol, we have several options:

1. USB Traffic Capture (Recommended):
   - Install USBPcap: https://desowin.org/usbpcap/
   - Use Wireshark to capture USB traffic
   - Click "Turn On All" in Neewer app and capture the packets
   
2. API Monitor:
   - Use API Monitor to hook Send_RF_DATA calls
   - See the exact buffer contents being sent
   
3. DLL Proxy/Hook:
   - Create a proxy DLL that logs all calls
   - Rename original to Set_Dongle_RF_API_x64_original.dll
   - Our proxy forwards calls and logs data

4. Frida Instrumentation:
   - Use Frida to hook the running process
   - Intercept Send_RF_DATA calls in real-time

Would you like me to set up any of these approaches?
""")


def main() -> None:
    dll = load_dll()
    
    # Verify connection
    get_usb_state = dll.Get_USB_State
    get_usb_state.restype = ctypes.c_int
    state = get_usb_state()
    print(f"USB Dongle State: {'Connected' if state == 1 else 'Disconnected'}")
    
    if state != 1:
        print("Dongle not connected - please plug it in!")
        return
    
    test_send_signatures(dll)
    examine_database_for_clues()
    suggest_next_steps()


if __name__ == "__main__":
    main()


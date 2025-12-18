"""Simple Neewer light on/off control via the 2.4GHz dongle."""

import ctypes
import sys
from pathlib import Path

NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")
DLL_PATH = NEEWER_DIR / "Set_Dongle_RF_API_x64.dll"

# On/Off command packet (32 bytes)
# Format: 77 58 01 85 01 56 + 26 zero bytes
ON_OFF_PACKET = bytes([0x77, 0x58, 0x01, 0x85, 0x01, 0x56]) + bytes(26)


def load_dll() -> ctypes.CDLL:
    """Load the Neewer RF API DLL."""
    if not DLL_PATH.exists():
        raise FileNotFoundError(f"DLL not found: {DLL_PATH}")
    return ctypes.CDLL(str(DLL_PATH))


def is_dongle_connected(dll: ctypes.CDLL) -> bool:
    """Check if the USB dongle is connected."""
    get_usb_state = dll.Get_USB_State
    get_usb_state.restype = ctypes.c_int
    return get_usb_state() == 1


def toggle_lights(dll: ctypes.CDLL) -> bool:
    """Send the on/off toggle command to all lights."""
    send_rf_data = dll.Send_RF_DATA
    send_rf_data.restype = ctypes.c_int
    send_rf_data.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    
    # Create buffer from packet
    buffer = (ctypes.c_ubyte * len(ON_OFF_PACKET))(*ON_OFF_PACKET)
    
    # Send the command
    result = send_rf_data(buffer, len(ON_OFF_PACKET))
    return result == 0


def main() -> None:
    print("Neewer Light Control")
    print("=" * 40)
    
    # Load DLL
    try:
        dll = load_dll()
        print("✓ DLL loaded")
    except FileNotFoundError as e:
        print(f"✗ {e}")
        sys.exit(1)
    
    # Check dongle
    if not is_dongle_connected(dll):
        print("✗ Dongle not connected!")
        sys.exit(1)
    print("✓ Dongle connected")
    
    # Toggle lights
    print("\nToggling lights...")
    if toggle_lights(dll):
        print("✓ Command sent!")
    else:
        print("✗ Failed to send command")
        sys.exit(1)


if __name__ == "__main__":
    main()


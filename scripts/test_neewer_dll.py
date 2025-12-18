"""Test loading and calling the Neewer RF API DLL directly."""

import ctypes
from ctypes import wintypes
from pathlib import Path


NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")
DLL_PATH = NEEWER_DIR / "Set_Dongle_RF_API_x64.dll"


def test_dll_loading() -> None:
    """Try to load the DLL and examine its functions."""
    print("Testing Neewer RF API DLL")
    print("=" * 80)
    print(f"DLL Path: {DLL_PATH}")
    print(f"Exists: {DLL_PATH.exists()}")
    
    if not DLL_PATH.exists():
        print("DLL not found!")
        return
    
    try:
        # Load the DLL
        dll = ctypes.CDLL(str(DLL_PATH))
        print("DLL loaded successfully!")
        
        # Try to get function pointers
        print("\nExported Functions:")
        print("-" * 40)
        
        # Get_USB_State - likely returns connection status
        try:
            get_usb_state = dll.Get_USB_State
            print(f"  Get_USB_State: {get_usb_state}")
            
            # Try calling it - might return 0/1 for disconnected/connected
            # We need to figure out the signature
            # Common patterns: int Get_USB_State(void) or int Get_USB_State(int* state)
            get_usb_state.restype = ctypes.c_int
            get_usb_state.argtypes = []
            
            result = get_usb_state()
            print(f"    Called Get_USB_State() -> {result}")
            print(f"    (0 might mean disconnected, 1 might mean connected)")
            
        except Exception as e:
            print(f"  Get_USB_State error: {e}")
        
        # Send_RF_DATA - sends commands to devices
        try:
            send_rf_data = dll.Send_RF_DATA
            print(f"  Send_RF_DATA: {send_rf_data}")
            # Don't call this without knowing the signature - could crash or do unexpected things
            
        except Exception as e:
            print(f"  Send_RF_DATA error: {e}")
            
    except OSError as e:
        print(f"Failed to load DLL: {e}")
        print("\nThis might be because:")
        print("  1. Missing dependencies (other DLLs)")
        print("  2. Architecture mismatch (32-bit vs 64-bit)")
        print("  3. DLL initialization failed")


def test_hidapi_dll() -> None:
    """Test loading the hidapi DLL."""
    print("\n\nTesting HIDAPI DLL")
    print("=" * 80)
    
    hidapi_path = NEEWER_DIR / "hidapi.dll"
    print(f"DLL Path: {hidapi_path}")
    
    try:
        dll = ctypes.CDLL(str(hidapi_path))
        print("HIDAPI DLL loaded successfully!")
        
        # Initialize hidapi
        hid_init = dll.hid_init
        hid_init.restype = ctypes.c_int
        result = hid_init()
        print(f"  hid_init() -> {result}")
        
        # Get version
        hid_version_str = dll.hid_version_str
        hid_version_str.restype = ctypes.c_char_p
        version = hid_version_str()
        print(f"  hid_version_str() -> {version.decode() if version else 'N/A'}")
        
    except Exception as e:
        print(f"Error: {e}")


def main() -> None:
    test_dll_loading()
    test_hidapi_dll()


if __name__ == "__main__":
    main()


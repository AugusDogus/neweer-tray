#!/usr/bin/env python3
"""
Test using BLE_USB_LIB_API_x64.dll directly to send data.
"""

import ctypes
import sys
from pathlib import Path

NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")
BLE_USB_DLL_PATH = NEEWER_DIR / "BLE_USB_LIB_API_x64.dll"
RF_DLL_PATH = NEEWER_DIR / "Set_Dongle_RF_API_x64.dll"

# On/Off command packet (32 bytes)
ON_OFF_PACKET = bytes([0x77, 0x58, 0x01, 0x85, 0x01, 0x56]) + bytes(26)

def test_ble_usb_lib():
    """Test the BLE USB library."""
    print("=" * 60)
    print("Testing BLE_USB_LIB_API_x64.dll")
    print("=" * 60)
    
    if not BLE_USB_DLL_PATH.exists():
        print(f"DLL not found: {BLE_USB_DLL_PATH}")
        return
    
    try:
        dll = ctypes.CDLL(str(BLE_USB_DLL_PATH))
        print(f"✓ Loaded {BLE_USB_DLL_PATH.name}")
    except Exception as e:
        print(f"✗ Failed to load DLL: {e}")
        return
    
    # Try init_usb
    try:
        init_usb = dll.init_usb
        init_usb.restype = ctypes.c_int
        result = init_usb()
        print(f"init_usb() returned: {result}")
    except Exception as e:
        print(f"init_usb failed: {e}")
    
    # Try Send_Data_Func
    try:
        send_data = dll.Send_Data_Func
        send_data.restype = ctypes.c_int
        # We don't know the exact signature, let's try common ones
        
        # Try with buffer and length
        buffer = (ctypes.c_ubyte * len(ON_OFF_PACKET))(*ON_OFF_PACKET)
        
        print("\nTrying Send_Data_Func with various signatures...")
        
        # Try: Send_Data_Func(buffer, length)
        try:
            send_data.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
            result = send_data(buffer, len(ON_OFF_PACKET))
            print(f"  Send_Data_Func(buffer, len) returned: {result}")
        except Exception as e:
            print(f"  Send_Data_Func(buffer, len) failed: {e}")
        
    except Exception as e:
        print(f"Send_Data_Func failed: {e}")

def test_rf_dll_internals():
    """Examine the RF DLL more closely."""
    print("\n" + "=" * 60)
    print("Testing Set_Dongle_RF_API_x64.dll internals")
    print("=" * 60)
    
    if not RF_DLL_PATH.exists():
        print(f"DLL not found: {RF_DLL_PATH}")
        return
    
    try:
        dll = ctypes.CDLL(str(RF_DLL_PATH))
        print(f"✓ Loaded {RF_DLL_PATH.name}")
    except Exception as e:
        print(f"✗ Failed to load DLL: {e}")
        return
    
    # Check Get_USB_State
    try:
        get_usb_state = dll.Get_USB_State
        get_usb_state.restype = ctypes.c_int
        state = get_usb_state()
        print(f"Get_USB_State() returned: {state} ({'connected' if state == 1 else 'disconnected'})")
    except Exception as e:
        print(f"Get_USB_State failed: {e}")
    
    # Send the command
    try:
        send_rf_data = dll.Send_RF_DATA
        send_rf_data.restype = ctypes.c_int
        send_rf_data.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        
        buffer = (ctypes.c_ubyte * len(ON_OFF_PACKET))(*ON_OFF_PACKET)
        result = send_rf_data(buffer, len(ON_OFF_PACKET))
        print(f"Send_RF_DATA() returned: {result} ({'success' if result == 0 else 'failed'})")
        
        if result == 0:
            print("\n✓ Lights should have toggled!")
    except Exception as e:
        print(f"Send_RF_DATA failed: {e}")

if __name__ == "__main__":
    test_ble_usb_lib()
    test_rf_dll_internals()


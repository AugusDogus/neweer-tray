#!/usr/bin/env python3
"""
Simple script to trigger Send_RF_DATA for Frida tracing.
Frida spawns this script and attaches before it runs.
"""

import ctypes
import os
import time
from pathlib import Path

NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")
RF_DLL_PATH = NEEWER_DIR / "Set_Dongle_RF_API_x64.dll"

ON_OFF_PACKET = bytes([0x77, 0x58, 0x01, 0x85, 0x01, 0x56]) + bytes(26)

print(f"PID: {os.getpid()}")
print("Loading DLL...")

dll = ctypes.CDLL(str(RF_DLL_PATH))
print("DLL loaded")

# Small delay to let Frida hooks settle
time.sleep(0.5)

print("\nChecking USB state...")
get_usb_state = dll.Get_USB_State
get_usb_state.restype = ctypes.c_int
state = get_usb_state()
print(f"Get_USB_State() = {state}")

print("\nSending RF data...")
send_rf_data = dll.Send_RF_DATA
send_rf_data.restype = ctypes.c_int
send_rf_data.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]

buffer = (ctypes.c_ubyte * len(ON_OFF_PACKET))(*ON_OFF_PACKET)
result = send_rf_data(buffer, len(ON_OFF_PACKET))
print(f"Send_RF_DATA() = {result}")

print("\nDone!")

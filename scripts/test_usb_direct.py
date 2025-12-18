#!/usr/bin/env python3
"""
Test direct USB communication with the Neewer dongle using WinUSB-style access.
"""

import ctypes
from ctypes import wintypes

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_FLAG_OVERLAPPED = 0x40000000

# IOCTL codes for HID
# HID_SET_OUTPUT_REPORT = CTL_CODE(FILE_DEVICE_KEYBOARD, 0x0010, METHOD_BUFFERED, FILE_ANY_ACCESS)
# FILE_DEVICE_KEYBOARD = 0x0B
# METHOD_BUFFERED = 0
# FILE_ANY_ACCESS = 0
# CTL_CODE = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
IOCTL_HID_SET_OUTPUT_REPORT = 0x000B0010  # ((0x0B << 16) | (0 << 14) | (0x10 << 2) | 0)

# Actually for HID class:
# IOCTL_HID_SET_OUTPUT_REPORT = 0x000B0191
# Let's calculate: FILE_DEVICE_KEYBOARD=0x0B, Function=0x64 (100), METHOD_OUT_DIRECT=2
# = (0x0B << 16) | (0 << 14) | (0x64 << 2) | 2 = 0x000B0192
# Or using METHOD_BUFFERED: (0x0B << 16) | (0 << 14) | (0x64 << 2) | 0 = 0x000B0190

kernel32 = ctypes.windll.kernel32

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
CreateFileW.restype = wintypes.HANDLE

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
DeviceIoControl.restype = wintypes.BOOL

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
WriteFile.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetLastError = kernel32.GetLastError
GetLastError.argtypes = []
GetLastError.restype = wintypes.DWORD

# The device path pattern (instance ID varies per system)
# Format: \\?\hid#vid_0581&pid_011d#<instance_id>#{4d1e55b2-f16f-11cf-88cb-001111000030}
# Use test_direct_protocol.py for dynamic discovery
NEEWER_HID_PATH = r"\\?\hid#vid_0581&pid_011d#<INSTANCE_ID>#{4d1e55b2-f16f-11cf-88cb-001111000030}"

# The on/off toggle packet
ON_OFF_DATA = bytes([
    0x77, 0x58, 0x01, 0x85, 0x01, 0x56,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

def try_various_ioctls(handle):
    """Try various IOCTL codes to send data."""
    
    # Various IOCTL codes to try
    ioctls = [
        (0x000B0191, "IOCTL_HID_SET_OUTPUT_REPORT (0x000B0191)"),
        (0x000B0190, "IOCTL_HID_SET_OUTPUT_REPORT_BUFFERED"),
        (0x000B0192, "IOCTL_HID_SET_OUTPUT_REPORT_DIRECT"),
        (0x000B0010, "Custom 0x000B0010"),
        (0x000B0014, "Custom 0x000B0014"),
        (0x221003, "IOCTL_USB_SUBMIT_URB"),
    ]
    
    # Try different packet formats
    packets = [
        (ON_OFF_DATA, "32 bytes raw"),
        (bytes([0x00]) + ON_OFF_DATA, "33 bytes with report ID 0"),
        (bytes([0x00]) + ON_OFF_DATA + bytes(31), "64 bytes with report ID 0"),
    ]
    
    for ioctl, ioctl_name in ioctls:
        for packet, packet_name in packets:
            print(f"\nTrying {ioctl_name} with {packet_name}...")
            
            packet_buffer = (ctypes.c_ubyte * len(packet))(*packet)
            bytes_returned = wintypes.DWORD()
            
            result = DeviceIoControl(
                handle,
                ioctl,
                ctypes.byref(packet_buffer),
                len(packet),
                None,
                0,
                ctypes.byref(bytes_returned),
                None
            )
            
            if result:
                print(f"  SUCCESS! Bytes returned: {bytes_returned.value}")
                return True
            else:
                error = GetLastError()
                print(f"  Failed, error: {error}")
    
    return False

def main():
    print("=" * 60)
    print("Neewer USB Direct IOCTL Test")
    print("=" * 60)
    
    print(f"\nOpening device: {NEEWER_HID_PATH}")
    
    handle = CreateFileW(
        NEEWER_HID_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        error = GetLastError()
        print(f"Failed to open device, error: {error}")
        return
    
    print("Device opened successfully")
    
    try:
        success = try_various_ioctls(handle)
        
        if success:
            print("\n✓ Command sent successfully!")
        else:
            print("\n✗ All IOCTL attempts failed")
    finally:
        CloseHandle(handle)

if __name__ == "__main__":
    main()


#!/usr/bin/env python3
"""
Test direct HID communication using Windows API (ctypes).
"""

import ctypes
from ctypes import wintypes
import struct

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1

# SetupAPI constants
DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010

# HID GUID: {4D1E55B2-F16F-11CF-88CB-001111000030}
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

HID_GUID = GUID(0x4D1E55B2, 0xF16F, 0x11CF, (ctypes.c_ubyte * 8)(0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30))

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", wintypes.DWORD),
        ("Reserved", ctypes.POINTER(ctypes.c_ulong)),
    ]

class SP_DEVICE_INTERFACE_DETAIL_DATA_W(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("DevicePath", ctypes.c_wchar * 260),
    ]

class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.DWORD),
        ("VendorID", ctypes.c_ushort),
        ("ProductID", ctypes.c_ushort),
        ("VersionNumber", ctypes.c_ushort),
    ]

# Load DLLs
setupapi = ctypes.windll.setupapi
hid = ctypes.windll.hid
kernel32 = ctypes.windll.kernel32

# SetupAPI functions
SetupDiGetClassDevsW = setupapi.SetupDiGetClassDevsW
SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
SetupDiGetClassDevsW.restype = wintypes.HANDLE

SetupDiEnumDeviceInterfaces = setupapi.SetupDiEnumDeviceInterfaces
SetupDiEnumDeviceInterfaces.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL

SetupDiGetDeviceInterfaceDetailW = setupapi.SetupDiGetDeviceInterfaceDetailW
SetupDiGetDeviceInterfaceDetailW.argtypes = [wintypes.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.POINTER(SP_DEVICE_INTERFACE_DETAIL_DATA_W), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL

SetupDiDestroyDeviceInfoList = setupapi.SetupDiDestroyDeviceInfoList
SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

# HID functions
HidD_GetAttributes = hid.HidD_GetAttributes
HidD_GetAttributes.argtypes = [wintypes.HANDLE, ctypes.POINTER(HIDD_ATTRIBUTES)]
HidD_GetAttributes.restype = wintypes.BOOL

HidD_SetOutputReport = hid.HidD_SetOutputReport
HidD_SetOutputReport.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.ULONG]
HidD_SetOutputReport.restype = wintypes.BOOL

# Kernel32 functions
CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
CreateFileW.restype = wintypes.HANDLE

WriteFile = kernel32.WriteFile
WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
WriteFile.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetLastError = kernel32.GetLastError
GetLastError.argtypes = []
GetLastError.restype = wintypes.DWORD

# Neewer constants
NEEWER_VID = 0x0581
NEEWER_PID = 0x011D

# The on/off toggle packet (32 bytes)
ON_OFF_PACKET = bytes([
    0x77, 0x58, 0x01, 0x85, 0x01, 0x56,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

def find_neewer_dongle():
    """Find the Neewer dongle and return its device path."""
    dev_info = SetupDiGetClassDevsW(ctypes.byref(HID_GUID), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if dev_info == INVALID_HANDLE_VALUE:
        print("SetupDiGetClassDevsW failed")
        return None
    
    try:
        device_index = 0
        while True:
            interface_data = SP_DEVICE_INTERFACE_DATA()
            interface_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            
            if not SetupDiEnumDeviceInterfaces(dev_info, None, ctypes.byref(HID_GUID), device_index, ctypes.byref(interface_data)):
                break
            
            # Get required size
            required_size = wintypes.DWORD()
            SetupDiGetDeviceInterfaceDetailW(dev_info, ctypes.byref(interface_data), None, 0, ctypes.byref(required_size), None)
            
            if required_size.value == 0:
                device_index += 1
                continue
            
            # Get device path
            detail_data = SP_DEVICE_INTERFACE_DETAIL_DATA_W()
            detail_data.cbSize = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6  # Different on 32/64-bit
            
            if not SetupDiGetDeviceInterfaceDetailW(dev_info, ctypes.byref(interface_data), ctypes.byref(detail_data), required_size.value, None, None):
                device_index += 1
                continue
            
            device_path = detail_data.DevicePath
            
            # Try to open and check VID/PID
            handle = CreateFileW(device_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
            if handle != INVALID_HANDLE_VALUE:
                attrs = HIDD_ATTRIBUTES()
                attrs.Size = ctypes.sizeof(HIDD_ATTRIBUTES)
                
                if HidD_GetAttributes(handle, ctypes.byref(attrs)):
                    if attrs.VendorID == NEEWER_VID and attrs.ProductID == NEEWER_PID:
                        print(f"Found Neewer dongle: {device_path}")
                        return handle, device_path
                
                CloseHandle(handle)
            
            device_index += 1
    finally:
        SetupDiDestroyDeviceInfoList(dev_info)
    
    return None

def toggle_lights():
    """Send the on/off toggle command."""
    result = find_neewer_dongle()
    if not result:
        print(f"Neewer dongle not found (VID: 0x{NEEWER_VID:04x}, PID: 0x{NEEWER_PID:04x})")
        return False
    
    handle, device_path = result
    
    try:
        # Try HidD_SetOutputReport first
        print(f"Trying HidD_SetOutputReport...")
        packet_buffer = (ctypes.c_ubyte * len(ON_OFF_PACKET))(*ON_OFF_PACKET)
        
        if HidD_SetOutputReport(handle, ctypes.byref(packet_buffer), len(ON_OFF_PACKET)):
            print("SUCCESS via HidD_SetOutputReport!")
            return True
        else:
            error = GetLastError()
            print(f"HidD_SetOutputReport failed, error: {error}")
        
        # Try with report ID 0 prepended
        print(f"Trying HidD_SetOutputReport with report ID 0...")
        packet_with_id = bytes([0x00]) + ON_OFF_PACKET
        packet_buffer2 = (ctypes.c_ubyte * len(packet_with_id))(*packet_with_id)
        
        if HidD_SetOutputReport(handle, ctypes.byref(packet_buffer2), len(packet_with_id)):
            print("SUCCESS via HidD_SetOutputReport with report ID!")
            return True
        else:
            error = GetLastError()
            print(f"HidD_SetOutputReport with report ID failed, error: {error}")
        
        # Try WriteFile
        print(f"Trying WriteFile...")
        bytes_written = wintypes.DWORD()
        
        if WriteFile(handle, ctypes.byref(packet_buffer), len(ON_OFF_PACKET), ctypes.byref(bytes_written), None):
            print(f"SUCCESS via WriteFile! Bytes written: {bytes_written.value}")
            return True
        else:
            error = GetLastError()
            print(f"WriteFile failed, error: {error}")
        
        # Try WriteFile with report ID
        print(f"Trying WriteFile with report ID 0...")
        if WriteFile(handle, ctypes.byref(packet_buffer2), len(packet_with_id), ctypes.byref(bytes_written), None):
            print(f"SUCCESS via WriteFile with report ID! Bytes written: {bytes_written.value}")
            return True
        else:
            error = GetLastError()
            print(f"WriteFile with report ID failed, error: {error}")
        
        return False
        
    finally:
        CloseHandle(handle)

if __name__ == "__main__":
    print("=" * 60)
    print("Neewer Win32 HID Test")
    print("=" * 60)
    
    success = toggle_lights()
    
    if success:
        print("\n✓ Command sent successfully!")
    else:
        print("\n✗ Failed to send command")


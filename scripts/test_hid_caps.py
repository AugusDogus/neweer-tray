#!/usr/bin/env python3
"""
Query HID device capabilities to understand the correct report format.
"""

import ctypes
from ctypes import wintypes

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1
DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010

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

class HIDP_CAPS(ctypes.Structure):
    _fields_ = [
        ("Usage", ctypes.c_ushort),
        ("UsagePage", ctypes.c_ushort),
        ("InputReportByteLength", ctypes.c_ushort),
        ("OutputReportByteLength", ctypes.c_ushort),
        ("FeatureReportByteLength", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort * 17),
        ("NumberLinkCollectionNodes", ctypes.c_ushort),
        ("NumberInputButtonCaps", ctypes.c_ushort),
        ("NumberInputValueCaps", ctypes.c_ushort),
        ("NumberInputDataIndices", ctypes.c_ushort),
        ("NumberOutputButtonCaps", ctypes.c_ushort),
        ("NumberOutputValueCaps", ctypes.c_ushort),
        ("NumberOutputDataIndices", ctypes.c_ushort),
        ("NumberFeatureButtonCaps", ctypes.c_ushort),
        ("NumberFeatureValueCaps", ctypes.c_ushort),
        ("NumberFeatureDataIndices", ctypes.c_ushort),
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

HidD_GetPreparsedData = hid.HidD_GetPreparsedData
HidD_GetPreparsedData.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
HidD_GetPreparsedData.restype = wintypes.BOOL

HidD_FreePreparsedData = hid.HidD_FreePreparsedData
HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
HidD_FreePreparsedData.restype = wintypes.BOOL

HidP_GetCaps = hid.HidP_GetCaps
HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(HIDP_CAPS)]
HidP_GetCaps.restype = ctypes.c_long  # NTSTATUS

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

# The on/off toggle packet
ON_OFF_DATA = bytes([
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
            
            required_size = wintypes.DWORD()
            SetupDiGetDeviceInterfaceDetailW(dev_info, ctypes.byref(interface_data), None, 0, ctypes.byref(required_size), None)
            
            if required_size.value == 0:
                device_index += 1
                continue
            
            detail_data = SP_DEVICE_INTERFACE_DETAIL_DATA_W()
            detail_data.cbSize = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
            
            if not SetupDiGetDeviceInterfaceDetailW(dev_info, ctypes.byref(interface_data), ctypes.byref(detail_data), required_size.value, None, None):
                device_index += 1
                continue
            
            device_path = detail_data.DevicePath
            
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

def get_hid_caps(handle):
    """Get HID device capabilities."""
    preparsed_data = ctypes.c_void_p()
    
    if not HidD_GetPreparsedData(handle, ctypes.byref(preparsed_data)):
        print(f"HidD_GetPreparsedData failed, error: {GetLastError()}")
        return None
    
    try:
        caps = HIDP_CAPS()
        status = HidP_GetCaps(preparsed_data, ctypes.byref(caps))
        
        if status != 0:  # HIDP_STATUS_SUCCESS = 0
            print(f"HidP_GetCaps failed, status: {status}")
            return None
        
        return caps
    finally:
        HidD_FreePreparsedData(preparsed_data)

def toggle_lights_with_correct_size(handle, output_report_length):
    """Send the on/off command with the correct report size."""
    
    # The output report includes the report ID (1 byte) + data
    # Report ID 0 means no report ID in the descriptor
    
    print(f"\nAttempting to send command with output report length: {output_report_length}")
    
    # Create buffer of correct size
    # First byte is report ID (use 0 if not specified)
    packet = bytearray(output_report_length)
    packet[0] = 0x00  # Report ID
    
    # Copy our data starting at position 1
    data_len = min(len(ON_OFF_DATA), output_report_length - 1)
    packet[1:1+data_len] = ON_OFF_DATA[:data_len]
    
    print(f"Packet ({len(packet)} bytes): {packet[:16].hex()}...")
    
    packet_buffer = (ctypes.c_ubyte * len(packet))(*packet)
    
    # Try HidD_SetOutputReport
    print("Trying HidD_SetOutputReport...")
    if HidD_SetOutputReport(handle, ctypes.byref(packet_buffer), len(packet)):
        print("SUCCESS via HidD_SetOutputReport!")
        return True
    else:
        error = GetLastError()
        print(f"HidD_SetOutputReport failed, error: {error}")
    
    # Try WriteFile
    print("Trying WriteFile...")
    bytes_written = wintypes.DWORD()
    if WriteFile(handle, ctypes.byref(packet_buffer), len(packet), ctypes.byref(bytes_written), None):
        print(f"SUCCESS via WriteFile! Bytes written: {bytes_written.value}")
        return True
    else:
        error = GetLastError()
        print(f"WriteFile failed, error: {error}")
    
    return False

def main():
    print("=" * 60)
    print("Neewer HID Capabilities Query")
    print("=" * 60)
    
    result = find_neewer_dongle()
    if not result:
        print(f"Neewer dongle not found (VID: 0x{NEEWER_VID:04x}, PID: 0x{NEEWER_PID:04x})")
        return
    
    handle, device_path = result
    
    try:
        caps = get_hid_caps(handle)
        if caps:
            print(f"\nHID Capabilities:")
            print(f"  Usage: 0x{caps.Usage:04x}")
            print(f"  UsagePage: 0x{caps.UsagePage:04x}")
            print(f"  InputReportByteLength: {caps.InputReportByteLength}")
            print(f"  OutputReportByteLength: {caps.OutputReportByteLength}")
            print(f"  FeatureReportByteLength: {caps.FeatureReportByteLength}")
            
            if caps.OutputReportByteLength > 0:
                success = toggle_lights_with_correct_size(handle, caps.OutputReportByteLength)
                if success:
                    print("\n✓ Command sent successfully!")
                else:
                    print("\n✗ Failed to send command")
            else:
                print("\nDevice has no output reports!")
        else:
            print("Failed to get HID capabilities")
    finally:
        CloseHandle(handle)

if __name__ == "__main__":
    main()


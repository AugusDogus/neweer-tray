#!/usr/bin/env python3
"""Debug HID device enumeration to see what we're finding."""

import ctypes
from ctypes import wintypes

# Neewer dongle identifiers
NEEWER_VID = 0x0581
NEEWER_PID = 0x011D

# HID device interface GUID: {4D1E55B2-F16F-11CF-88CB-001111000030}
HID_GUID = (0x4D1E55B2, 0xF16F, 0x11CF, (0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30))

# Windows API constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
DIGCF_PRESENT = 0x00000002
DIGCF_DEVICEINTERFACE = 0x00000010
ERROR_NO_MORE_ITEMS = 259

# Windows API
kernel32 = ctypes.windll.kernel32
setupapi = ctypes.windll.setupapi
hid = ctypes.windll.hid


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", wintypes.DWORD),
        ("Reserved", ctypes.POINTER(ctypes.c_ulong)),
    ]


class SP_DEVICE_INTERFACE_DETAIL_DATA_A(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("DevicePath", ctypes.c_char * 512),
    ]


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.ULONG),
        ("VendorID", wintypes.USHORT),
        ("ProductID", wintypes.USHORT),
        ("VersionNumber", wintypes.USHORT),
    ]


# Function signatures
setupapi.SetupDiGetClassDevsA.argtypes = [ctypes.POINTER(GUID), ctypes.c_char_p, wintypes.HWND, wintypes.DWORD]
setupapi.SetupDiGetClassDevsA.restype = wintypes.HANDLE

setupapi.SetupDiEnumDeviceInterfaces.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL

setupapi.SetupDiGetDeviceInterfaceDetailA.argtypes = [wintypes.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.POINTER(SP_DEVICE_INTERFACE_DETAIL_DATA_A), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
setupapi.SetupDiGetDeviceInterfaceDetailA.restype = wintypes.BOOL

setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

hid.HidD_GetAttributes.argtypes = [wintypes.HANDLE, ctypes.POINTER(HIDD_ATTRIBUTES)]
hid.HidD_GetAttributes.restype = wintypes.BOOLEAN

kernel32.CreateFileA.argtypes = [ctypes.c_char_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileA.restype = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.GetLastError.argtypes = []
kernel32.GetLastError.restype = wintypes.DWORD


def make_hid_guid() -> GUID:
    """Create the HID device interface GUID."""
    guid = GUID()
    guid.Data1 = HID_GUID[0]
    guid.Data2 = HID_GUID[1]
    guid.Data3 = HID_GUID[2]
    for i, b in enumerate(HID_GUID[3]):
        guid.Data4[i] = b
    return guid


def enumerate_all_hid_devices() -> None:
    """Enumerate all HID devices and print their info."""
    guid = make_hid_guid()
    
    print(f"HID GUID: {{{HID_GUID[0]:08x}-{HID_GUID[1]:04x}-{HID_GUID[2]:04x}-{bytes(HID_GUID[3]).hex()}}}")
    
    # Get device info set for HID devices
    dev_info = setupapi.SetupDiGetClassDevsA(
        ctypes.byref(guid),
        None,
        None,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    )
    
    if dev_info == INVALID_HANDLE_VALUE:
        print(f"SetupDiGetClassDevsA failed: {kernel32.GetLastError()}")
        return
    
    print(f"Device info handle: {dev_info}")
    print()
    
    try:
        index = 0
        found_neewer = False
        
        while True:
            # Enumerate device interfaces
            interface_data = SP_DEVICE_INTERFACE_DATA()
            interface_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            
            if not setupapi.SetupDiEnumDeviceInterfaces(dev_info, None, ctypes.byref(guid), index, ctypes.byref(interface_data)):
                error = kernel32.GetLastError()
                if error == ERROR_NO_MORE_ITEMS:
                    print(f"\nEnumerated {index} devices total.")
                    break
                print(f"SetupDiEnumDeviceInterfaces failed at index {index}: {error}")
                break
            
            # Get device interface detail
            detail_data = SP_DEVICE_INTERFACE_DETAIL_DATA_A()
            detail_data.cbSize = 5  # sizeof(DWORD) + sizeof(CHAR) on x64
            required_size = wintypes.DWORD()
            
            if not setupapi.SetupDiGetDeviceInterfaceDetailA(
                dev_info,
                ctypes.byref(interface_data),
                ctypes.byref(detail_data),
                ctypes.sizeof(detail_data),
                ctypes.byref(required_size),
                None
            ):
                error = kernel32.GetLastError()
                if error != 122:  # ERROR_INSUFFICIENT_BUFFER is OK
                    print(f"[{index}] GetDeviceInterfaceDetail failed: {error}")
                    index += 1
                    continue
            
            device_path = detail_data.DevicePath
            path_str = device_path.decode('ascii', errors='replace')
            
            # Check if path contains our VID/PID
            is_neewer_path = "vid_0581" in path_str.lower() and "pid_011d" in path_str.lower()
            
            # Open device to check VID/PID
            handle = kernel32.CreateFileA(
                device_path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            
            vid = pid = 0
            open_error = 0
            
            if handle != INVALID_HANDLE_VALUE:
                attrs = HIDD_ATTRIBUTES()
                attrs.Size = ctypes.sizeof(HIDD_ATTRIBUTES)
                
                if hid.HidD_GetAttributes(handle, ctypes.byref(attrs)):
                    vid = attrs.VendorID
                    pid = attrs.ProductID
                
                kernel32.CloseHandle(handle)
            else:
                open_error = kernel32.GetLastError()
            
            # Print info for Neewer device or if path matches
            if vid == NEEWER_VID and pid == NEEWER_PID:
                found_neewer = True
                print(f"[{index}] *** NEEWER DONGLE FOUND ***")
                print(f"     VID={vid:04x} PID={pid:04x}")
                print(f"     Path: {path_str}")
            elif is_neewer_path:
                print(f"[{index}] Path matches VID/PID but couldn't verify:")
                print(f"     Path: {path_str}")
                if open_error:
                    print(f"     Open error: {open_error}")
            
            index += 1
        
        if not found_neewer:
            print("\n*** Neewer dongle NOT found in enumeration ***")
            print("Searching for any path containing 'vid_0581'...")
            
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(dev_info)


def main() -> None:
    print("=" * 60)
    print("Debug HID Device Enumeration")
    print("=" * 60)
    print(f"Looking for: VID={NEEWER_VID:04x} PID={NEEWER_PID:04x}")
    print()
    
    enumerate_all_hid_devices()


if __name__ == "__main__":
    main()


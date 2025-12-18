#!/usr/bin/env python3
"""
Direct HID communication with Neewer dongle using the discovered protocol.

Protocol:
- Device: VID 0x0581, PID 0x011D
- Communication: WriteFile with 64-byte packet:
  - Bytes 0-6: Header (ba 70 24 00 00 00 00)
  - Bytes 7+: Command data (77 58 01 85 01 56 ...)

This script dynamically discovers the device path by enumerating HID devices.
"""

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
ERROR_INSUFFICIENT_BUFFER = 122

# Windows API
kernel32 = ctypes.windll.kernel32
setupapi = ctypes.windll.setupapi


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


# Function signatures
setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.POINTER(GUID), wintypes.LPCWSTR, wintypes.HWND, wintypes.DWORD]
setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE

setupapi.SetupDiEnumDeviceInterfaces.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)]
setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL

setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [wintypes.HANDLE, ctypes.POINTER(SP_DEVICE_INTERFACE_DATA), ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL

setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

kernel32.CreateFileA.argtypes = [ctypes.c_char_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
kernel32.CreateFileA.restype = wintypes.HANDLE

kernel32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
kernel32.WriteFile.restype = wintypes.BOOL

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


def find_neewer_dongle() -> bytes | None:
    """
    Enumerate HID devices and find the Neewer dongle by VID/PID in the path.
    Returns the device path as bytes, or None if not found.
    """
    guid = make_hid_guid()
    
    # Get device info set for HID devices
    dev_info = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid),
        None,
        None,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    )
    
    if dev_info == INVALID_HANDLE_VALUE:
        print(f"SetupDiGetClassDevsW failed: {kernel32.GetLastError()}")
        return None
    
    # VID/PID pattern to look for in device path
    vid_pid_pattern = f"vid_{NEEWER_VID:04x}&pid_{NEEWER_PID:04x}".lower()
    
    try:
        index = 0
        while True:
            # Enumerate device interfaces
            interface_data = SP_DEVICE_INTERFACE_DATA()
            interface_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            
            if not setupapi.SetupDiEnumDeviceInterfaces(dev_info, None, ctypes.byref(guid), index, ctypes.byref(interface_data)):
                error = kernel32.GetLastError()
                if error == ERROR_NO_MORE_ITEMS:
                    break
                print(f"SetupDiEnumDeviceInterfaces failed: {error}")
                break
            
            # First call to get required size
            required_size = wintypes.DWORD()
            setupapi.SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                ctypes.byref(interface_data),
                None,
                0,
                ctypes.byref(required_size),
                None
            )
            
            if required_size.value == 0:
                index += 1
                continue
            
            # Allocate buffer for detail data
            # SP_DEVICE_INTERFACE_DETAIL_DATA_W has cbSize (DWORD) followed by DevicePath (WCHAR[])
            buffer_size = required_size.value
            buffer = ctypes.create_string_buffer(buffer_size)
            
            # Set cbSize - for SP_DEVICE_INTERFACE_DETAIL_DATA_W on x64, it's 8 bytes
            # (4 bytes for cbSize DWORD + 4 bytes padding before the WCHAR array)
            ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0] = 8
            
            if not setupapi.SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                ctypes.byref(interface_data),
                buffer,
                buffer_size,
                None,
                None
            ):
                error = kernel32.GetLastError()
                print(f"SetupDiGetDeviceInterfaceDetailW failed: {error}")
                index += 1
                continue
            
            # Extract device path (starts at offset 4, is a wide string)
            device_path_ptr = ctypes.cast(ctypes.addressof(buffer) + 4, ctypes.POINTER(ctypes.c_wchar))
            device_path = ctypes.wstring_at(device_path_ptr)
            
            # Check if this is our device by VID/PID in path
            if vid_pid_pattern in device_path.lower():
                print(f"Found Neewer dongle!")
                print(f"Device path: {device_path}")
                # Convert to bytes for CreateFileA
                return device_path.encode('ascii')
            
            index += 1
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(dev_info)
    
    return None


# Protocol header (discovered via Frida trace)
HEADER = bytes([0xba, 0x70, 0x24, 0x00, 0x00, 0x00, 0x00])

# On/Off command
ON_OFF_CMD = bytes([0x77, 0x58, 0x01, 0x85, 0x01, 0x56])


def build_packet(command: bytes) -> bytes:
    """Build a 64-byte packet with header + command."""
    packet = bytearray(64)
    packet[0:len(HEADER)] = HEADER
    packet[len(HEADER):len(HEADER)+len(command)] = command
    return bytes(packet)


def toggle_lights(device_path: bytes) -> bool:
    """Send the on/off toggle command directly to the dongle."""
    print(f"\nOpening device...")
    
    handle = kernel32.CreateFileA(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None
    )
    
    if handle == INVALID_HANDLE_VALUE:
        error = kernel32.GetLastError()
        print(f"Failed to open device, error: {error}")
        return False
    
    try:
        packet = build_packet(ON_OFF_CMD)
        print(f"Sending packet ({len(packet)} bytes):")
        print(f"  Header: {' '.join(f'{b:02x}' for b in packet[:7])}")
        print(f"  Command: {' '.join(f'{b:02x}' for b in packet[7:13])}")
        
        packet_buffer = (ctypes.c_ubyte * len(packet))(*packet)
        bytes_written = wintypes.DWORD()
        
        result = kernel32.WriteFile(handle, ctypes.byref(packet_buffer), len(packet), ctypes.byref(bytes_written), None)
        
        if result:
            print(f"SUCCESS! Wrote {bytes_written.value} bytes")
            return True
        else:
            error = kernel32.GetLastError()
            print(f"WriteFile failed, error: {error}")
            return False
    finally:
        kernel32.CloseHandle(handle)


def main() -> None:
    print("=" * 60)
    print("Neewer Direct Protocol - DLL-Free Implementation")
    print("=" * 60)
    print(f"Looking for dongle: VID={NEEWER_VID:04x} PID={NEEWER_PID:04x}")
    print()
    
    device_path = find_neewer_dongle()
    
    if device_path is None:
        print("\n✗ Neewer dongle not found!")
        print("  Make sure the 2.4GHz USB dongle is plugged in.")
        return
    
    success = toggle_lights(device_path)
    
    if success:
        print("\n✓ Lights should have toggled!")
    else:
        print("\n✗ Failed to toggle lights")


if __name__ == "__main__":
    main()

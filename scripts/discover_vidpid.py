"""Discover the Neewer dongle VID/PID by using the Neewer hidapi.dll directly."""

import ctypes
from ctypes import c_int, c_ushort, c_wchar_p, c_void_p, POINTER, Structure, c_char_p
from pathlib import Path


NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")


class hid_device_info(Structure):
    pass

hid_device_info._fields_ = [
    ("path", c_char_p),
    ("vendor_id", c_ushort),
    ("product_id", c_ushort),
    ("serial_number", c_wchar_p),
    ("release_number", c_ushort),
    ("manufacturer_string", c_wchar_p),
    ("product_string", c_wchar_p),
    ("usage_page", c_ushort),
    ("usage", c_ushort),
    ("interface_number", c_int),
    ("next", POINTER(hid_device_info)),
]


def main():
    print("Discovering Neewer Dongle VID/PID using Neewer's hidapi.dll")
    print("=" * 70)
    
    hidapi_path = NEEWER_DIR / "hidapi.dll"
    if not hidapi_path.exists():
        print(f"Error: hidapi.dll not found at {hidapi_path}")
        return
    
    # Load Neewer's hidapi.dll
    hidapi = ctypes.CDLL(str(hidapi_path))
    
    # Setup function signatures
    hidapi.hid_init.restype = c_int
    hidapi.hid_enumerate.argtypes = [c_ushort, c_ushort]
    hidapi.hid_enumerate.restype = POINTER(hid_device_info)
    hidapi.hid_free_enumeration.argtypes = [POINTER(hid_device_info)]
    
    # Initialize
    result = hidapi.hid_init()
    print(f"hid_init() -> {result}")
    
    # Enumerate ALL devices (VID=0, PID=0 means all)
    print("\nEnumerating all HID devices via Neewer's hidapi.dll:")
    print("-" * 70)
    
    devices = hidapi.hid_enumerate(0, 0)
    
    if not devices:
        print("No devices found!")
        return
    
    current = devices
    device_list = []
    while current:
        dev = current.contents
        info = {
            'vid': dev.vendor_id,
            'pid': dev.product_id,
            'path': dev.path.decode('utf-8') if dev.path else '',
            'manufacturer': dev.manufacturer_string or '',
            'product': dev.product_string or '',
            'usage_page': dev.usage_page,
            'usage': dev.usage,
            'interface': dev.interface_number,
        }
        device_list.append(info)
        
        if not dev.next:
            break
        current = dev.next
    
    hidapi.hid_free_enumeration(devices)
    
    # Print unique VID:PID combinations
    seen = set()
    for dev in device_list:
        key = (dev['vid'], dev['pid'])
        if key not in seen:
            seen.add(key)
            print(f"\nVID:PID = {dev['vid']:04X}:{dev['pid']:04X}")
            if dev['manufacturer']:
                print(f"  Manufacturer: {dev['manufacturer']}")
            if dev['product']:
                print(f"  Product: {dev['product']}")
            print(f"  Usage Page: 0x{dev['usage_page']:04X}, Usage: 0x{dev['usage']:04X}")
    
    print("\n" + "-" * 70)
    print(f"Total unique VID:PID: {len(seen)}")
    
    # Now let's check what the RF API DLL reports
    print("\n" + "=" * 70)
    print("Checking Set_Dongle_RF_API_x64.dll status:")
    print("-" * 70)
    
    rf_dll_path = NEEWER_DIR / "Set_Dongle_RF_API_x64.dll"
    if rf_dll_path.exists():
        rf_dll = ctypes.CDLL(str(rf_dll_path))
        rf_dll.Get_USB_State.restype = c_int
        state = rf_dll.Get_USB_State()
        print(f"Get_USB_State() -> {state} ({'Connected' if state == 1 else 'Disconnected'})")
        
        if state == 1:
            print("\nThe dongle IS connected according to the Neewer DLL!")
            print("But we need to find which HID device it is...")
            print("\nLook for devices that don't match your known hardware above.")


if __name__ == "__main__":
    main()


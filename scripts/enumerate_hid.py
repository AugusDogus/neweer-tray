"""Enumerate HID devices to find the Neewer 2.4GHz dongle."""

import hid

# Known Neewer VID (from earlier USB enumeration)
NEEWER_VID = 0x3434
NEEWER_PID = 0x0121


def enumerate_all_devices() -> None:
    """List all HID devices."""
    print("All HID Devices:")
    print("=" * 80)
    
    devices = hid.enumerate()
    
    for device in devices:
        vid = device['vendor_id']
        pid = device['product_id']
        manufacturer = device.get('manufacturer_string', 'N/A') or 'N/A'
        product = device.get('product_string', 'N/A') or 'N/A'
        path = device.get('path', b'').decode('utf-8', errors='ignore')
        interface = device.get('interface_number', -1)
        usage_page = device.get('usage_page', 0)
        usage = device.get('usage', 0)
        
        print(f"VID:PID = {vid:04X}:{pid:04X}")
        print(f"  Manufacturer: {manufacturer}")
        print(f"  Product: {product}")
        print(f"  Interface: {interface}")
        print(f"  Usage Page: 0x{usage_page:04X}, Usage: 0x{usage:04X}")
        print(f"  Path: {path[:80]}...")
        print()


def find_neewer_devices() -> None:
    """Find Neewer-specific HID devices."""
    print("\n" + "=" * 80)
    print("Neewer Devices (VID=0x3434):")
    print("=" * 80)
    
    devices = hid.enumerate(NEEWER_VID)
    
    if not devices:
        print("No Neewer devices found!")
        return
    
    for i, device in enumerate(devices):
        vid = device['vendor_id']
        pid = device['product_id']
        manufacturer = device.get('manufacturer_string', 'N/A') or 'N/A'
        product = device.get('product_string', 'N/A') or 'N/A'
        path = device.get('path', b'').decode('utf-8', errors='ignore')
        interface = device.get('interface_number', -1)
        usage_page = device.get('usage_page', 0)
        usage = device.get('usage', 0)
        
        print(f"\nDevice {i + 1}:")
        print(f"  VID:PID = {vid:04X}:{pid:04X}")
        print(f"  Manufacturer: {manufacturer}")
        print(f"  Product: {product}")
        print(f"  Interface: {interface}")
        print(f"  Usage Page: 0x{usage_page:04X}, Usage: 0x{usage:04X}")
        print(f"  Path: {path}")


def main() -> None:
    print("HID Device Enumeration for Neewer Reverse Engineering")
    print("=" * 80)
    
    # First show all devices
    enumerate_all_devices()
    
    # Then focus on Neewer
    find_neewer_devices()


if __name__ == "__main__":
    main()


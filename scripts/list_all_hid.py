"""List ALL HID devices to help identify the Neewer dongle."""

import hid


def main():
    print("All HID Devices")
    print("=" * 80)
    print()
    print("Please unplug the Neewer dongle, run this script,")
    print("then plug it back in and run again to see which device appears.")
    print()
    print("-" * 80)
    
    devices = hid.enumerate()
    
    # Group by VID:PID
    seen = set()
    for device in devices:
        vid = device['vendor_id']
        pid = device['product_id']
        key = (vid, pid)
        if key in seen:
            continue
        seen.add(key)
        
        manufacturer = device.get('manufacturer_string', '') or ''
        product = device.get('product_string', '') or ''
        
        print(f"VID:PID = {vid:04X}:{pid:04X}")
        if manufacturer:
            print(f"  Manufacturer: {manufacturer}")
        if product:
            print(f"  Product: {product}")
        print()

    print("-" * 80)
    print(f"Total unique VID:PID combinations: {len(seen)}")


if __name__ == "__main__":
    main()


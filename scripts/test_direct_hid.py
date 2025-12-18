#!/usr/bin/env python3
"""
Test direct HID communication with the Neewer dongle.
VID: 0x0581, PID: 0x011D
Packet: 77 58 01 85 01 56 (+ padding to 32 bytes)
"""

import hid

NEEWER_VID = 0x0581
NEEWER_PID = 0x011D

# The on/off toggle packet (32 bytes)
ON_OFF_PACKET = bytes([
    0x77, 0x58, 0x01, 0x85, 0x01, 0x56,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

def list_hid_devices():
    """List all HID devices to find the Neewer dongle."""
    print("Listing all HID devices...")
    devices = hid.enumerate()
    for d in devices:
        vid = d['vendor_id']
        pid = d['product_id']
        if vid == NEEWER_VID and pid == NEEWER_PID:
            print(f"  *** FOUND NEEWER DONGLE ***")
        print(f"  VID: 0x{vid:04x}, PID: 0x{pid:04x}, "
              f"Manufacturer: {d.get('manufacturer_string', 'N/A')}, "
              f"Product: {d.get('product_string', 'N/A')}, "
              f"Path: {d['path']}")
    return devices

def find_neewer_dongle():
    """Find and return the Neewer dongle device info."""
    devices = hid.enumerate(NEEWER_VID, NEEWER_PID)
    if devices:
        return devices[0]
    return None

def toggle_lights():
    """Send the on/off toggle command to the Neewer dongle."""
    device_info = find_neewer_dongle()
    if not device_info:
        print(f"Neewer dongle not found (VID: 0x{NEEWER_VID:04x}, PID: 0x{NEEWER_PID:04x})")
        return False
    
    print(f"Found Neewer dongle: {device_info['path']}")
    
    try:
        device = hid.device()
        device.open_path(device_info['path'])
        print("Opened device successfully")
        
        # Try sending with report ID 0 prepended (common for HID)
        packet_with_report_id = bytes([0x00]) + ON_OFF_PACKET
        
        print(f"Sending packet ({len(packet_with_report_id)} bytes): {packet_with_report_id[:10].hex()}...")
        
        # Try write() first
        try:
            result = device.write(packet_with_report_id)
            print(f"write() returned: {result}")
            if result > 0:
                print("SUCCESS! Lights should have toggled.")
                device.close()
                return True
        except Exception as e:
            print(f"write() failed: {e}")
        
        # Try send_feature_report
        try:
            result = device.send_feature_report(packet_with_report_id)
            print(f"send_feature_report() returned: {result}")
            if result > 0:
                print("SUCCESS via feature report!")
                device.close()
                return True
        except Exception as e:
            print(f"send_feature_report() failed: {e}")
        
        # Try without report ID
        print(f"Trying without report ID...")
        try:
            result = device.write(ON_OFF_PACKET)
            print(f"write() without report ID returned: {result}")
            if result > 0:
                print("SUCCESS!")
                device.close()
                return True
        except Exception as e:
            print(f"write() without report ID failed: {e}")
        
        device.close()
        return False
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Neewer Direct HID Test")
    print("=" * 60)
    
    # First list all devices
    list_hid_devices()
    print()
    
    # Try to toggle lights
    print("Attempting to toggle lights...")
    success = toggle_lights()
    
    if success:
        print("\n✓ Command sent successfully!")
    else:
        print("\n✗ Failed to send command")


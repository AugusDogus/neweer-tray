#!/usr/bin/env python3
"""
Test using pyusb/libusb to communicate with the Neewer dongle.
This bypasses the HID layer entirely and talks directly to USB.
"""

try:
    import usb.core
    import usb.util
except ImportError:
    print("pyusb not installed. Run: pip install pyusb")
    print("Also need libusb-win32 or WinUSB driver")
    exit(1)

NEEWER_VID = 0x0581
NEEWER_PID = 0x011D

# The on/off toggle packet
ON_OFF_DATA = bytes([
    0x77, 0x58, 0x01, 0x85, 0x01, 0x56,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])

def main():
    print("=" * 60)
    print("Neewer USB Direct Test (pyusb)")
    print("=" * 60)
    
    # Find the device
    dev = usb.core.find(idVendor=NEEWER_VID, idProduct=NEEWER_PID)
    
    if dev is None:
        print(f"Device not found (VID: 0x{NEEWER_VID:04x}, PID: 0x{NEEWER_PID:04x})")
        return
    
    print(f"Found device: {dev}")
    print(f"  Manufacturer: {dev.manufacturer}")
    print(f"  Product: {dev.product}")
    
    # Print configuration
    for cfg in dev:
        print(f"\nConfiguration {cfg.bConfigurationValue}:")
        for intf in cfg:
            print(f"  Interface {intf.bInterfaceNumber}, Alt {intf.bAlternateSetting}:")
            print(f"    Class: {intf.bInterfaceClass}, SubClass: {intf.bInterfaceSubClass}, Protocol: {intf.bInterfaceProtocol}")
            for ep in intf:
                print(f"    Endpoint 0x{ep.bEndpointAddress:02x}: {usb.util.endpoint_direction(ep.bEndpointAddress)}, Type: {usb.util.endpoint_type(ep.bmAttributes)}")
    
    # Try to set configuration and claim interface
    try:
        dev.set_configuration()
        print("\nConfiguration set")
    except Exception as e:
        print(f"Failed to set configuration: {e}")
    
    # Try to claim interface 0
    try:
        usb.util.claim_interface(dev, 0)
        print("Interface 0 claimed")
    except Exception as e:
        print(f"Failed to claim interface: {e}")
    
    # Find OUT endpoint
    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    
    ep_out = usb.util.find_descriptor(
        intf,
        custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
    )
    
    if ep_out:
        print(f"\nFound OUT endpoint: 0x{ep_out.bEndpointAddress:02x}")
        print(f"  Max packet size: {ep_out.wMaxPacketSize}")
        
        # Try to send data
        print(f"\nSending {len(ON_OFF_DATA)} bytes...")
        try:
            result = ep_out.write(ON_OFF_DATA)
            print(f"Wrote {result} bytes")
            print("\n✓ Command sent successfully!")
        except Exception as e:
            print(f"Write failed: {e}")
    else:
        print("No OUT endpoint found!")
    
    # Release interface
    try:
        usb.util.release_interface(dev, 0)
    except:
        pass

if __name__ == "__main__":
    main()


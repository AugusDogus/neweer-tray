"""Analyze the captured Neewer RF protocol packets."""

# Captured packets from Frida hook
PACKETS = [
    # (count, hex_data)
    (4,  "77 58 01 82 00 52"),  # XX=0x00, YY=0x52
    (7,  "77 58 01 82 01 53"),  # XX=0x01, YY=0x53
    (4,  "77 58 01 82 02 54"),  # XX=0x02, YY=0x54
    (3,  "77 58 01 82 03 55"),  # XX=0x03, YY=0x55
    (2,  "77 58 01 82 04 56"),  # XX=0x04, YY=0x56
    (2,  "77 58 01 82 05 57"),  # XX=0x05, YY=0x57
    (1,  "77 58 01 82 06 58"),  # XX=0x06, YY=0x58
    (2,  "77 58 01 82 08 5a"),  # XX=0x08, YY=0x5a
    (1,  "77 58 01 82 0b 5d"),  # XX=0x0b, YY=0x5d
    (2,  "77 58 01 82 0c 5e"),  # XX=0x0c, YY=0x5e
    (2,  "77 58 01 82 10 62"),  # XX=0x10, YY=0x62
    (1,  "77 58 01 82 13 65"),  # XX=0x13, YY=0x65
    (19, "77 58 01 85 01 56"),  # Different command type (0x85 vs 0x82)
]


def analyze_checksum():
    """Analyze the checksum pattern."""
    print("Checksum Analysis")
    print("=" * 60)
    print(f"{'Packet':<30} {'XX':>5} {'YY':>5} {'Sum':>5} {'XOR':>5}")
    print("-" * 60)
    
    for count, hex_data in PACKETS:
        bytes_data = bytes.fromhex(hex_data.replace(" ", ""))
        xx = bytes_data[4]
        yy = bytes_data[5]
        
        # Try different checksum algorithms
        simple_sum = sum(bytes_data[:5]) & 0xFF
        xor_all = 0
        for b in bytes_data[:5]:
            xor_all ^= b
        
        # The checksum appears to be: 0x52 + XX = YY
        # Let's verify: 0x52 + 0x00 = 0x52, 0x52 + 0x01 = 0x53, etc.
        calculated = 0x52 + xx
        match = "✓" if calculated == yy else "✗"
        
        print(f"{hex_data:<30} {xx:5d} {yy:5d} {simple_sum:5d} {calculated:5d} {match}")


def decode_protocol():
    """Decode the protocol structure."""
    print("\n\nProtocol Structure")
    print("=" * 60)
    print("""
Packet format (32 bytes total, first 6 bytes are significant):
    
    Byte 0: 0x77 - Magic/Header byte 1
    Byte 1: 0x58 - Magic/Header byte 2  
    Byte 2: 0x01 - Unknown (device type? always 0x01)
    Byte 3: Command type
            0x82 = Brightness/CCT control?
            0x85 = On/Off toggle?
    Byte 4: Value (channel? brightness level? 0x00-0x13 seen)
    Byte 5: Checksum = 0x52 + Byte[4]
    Bytes 6-31: Padding (zeros)
    
Checksum formula: checksum = 0x52 + value_byte
    """)


def generate_test_commands():
    """Generate test commands based on analysis."""
    print("\n\nTest Commands to Try")
    print("=" * 60)
    
    def make_packet(cmd_type: int, value: int) -> bytes:
        """Create a 32-byte packet."""
        checksum = (0x52 + value) & 0xFF
        packet = bytes([0x77, 0x58, 0x01, cmd_type, value, checksum])
        packet += bytes(26)  # Pad to 32 bytes
        return packet
    
    print("\nOn/Off commands (cmd_type=0x85):")
    for val in [0x00, 0x01]:
        pkt = make_packet(0x85, val)
        print(f"  Value {val}: {pkt[:8].hex(' ')}")
    
    print("\nBrightness commands (cmd_type=0x82):")
    for val in [0, 25, 50, 75, 100]:
        pkt = make_packet(0x82, val)
        print(f"  Brightness {val}%: {pkt[:8].hex(' ')}")
    
    print("\nChannel commands (if value=channel):")
    for ch in range(5):
        pkt = make_packet(0x82, ch)
        print(f"  Channel {ch}: {pkt[:8].hex(' ')}")


def main():
    analyze_checksum()
    decode_protocol()
    generate_test_commands()


if __name__ == "__main__":
    main()


"""Deep scan of all USB devices to find the Neewer dongle."""

import subprocess
import re


def get_all_usb_devices() -> None:
    """Get detailed info on all USB devices using PowerShell."""
    print("All USB Devices (Detailed):")
    print("=" * 80)
    
    # Get USB devices with full details
    ps_cmd = """
    Get-PnpDevice -Class USB | ForEach-Object {
        $device = $_
        $props = Get-PnpDeviceProperty -InstanceId $device.InstanceId -ErrorAction SilentlyContinue
        
        $vid = ($props | Where-Object KeyName -eq 'DEVPKEY_Device_BusReportedDeviceDesc').Data
        $hwids = ($props | Where-Object KeyName -eq 'DEVPKEY_Device_HardwareIds').Data
        
        [PSCustomObject]@{
            FriendlyName = $device.FriendlyName
            Status = $device.Status
            InstanceId = $device.InstanceId
            HardwareIds = ($hwids -join '; ')
        }
    } | Format-List
    """
    
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.stderr:
        print(f"Errors: {result.stderr}")


def get_hid_devices_detailed() -> None:
    """Get all HID devices with full hardware IDs."""
    print("\nAll HID Devices (Detailed):")
    print("=" * 80)
    
    ps_cmd = """
    Get-PnpDevice -Class HIDClass | ForEach-Object {
        $device = $_
        [PSCustomObject]@{
            FriendlyName = $device.FriendlyName
            Status = $device.Status
            InstanceId = $device.InstanceId
        }
    } | Where-Object { $_.Status -eq 'OK' } | Format-List
    """
    
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True
    )
    print(result.stdout)


def find_unknown_devices() -> None:
    """Find devices with unknown or generic names that might be Neewer."""
    print("\nUnknown/Generic USB Devices (potential Neewer):")
    print("=" * 80)
    
    ps_cmd = """
    Get-PnpDevice | Where-Object { 
        ($_.FriendlyName -like '*Unknown*' -or 
         $_.FriendlyName -like '*Generic*' -or
         $_.FriendlyName -like '*USB Composite*' -or
         $_.FriendlyName -like '*USB Input*' -or
         $_.FriendlyName -like '*HID-compliant vendor*') -and
        $_.Status -eq 'OK'
    } | Select-Object FriendlyName, InstanceId, Class | Format-List
    """
    
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True
    )
    print(result.stdout)


def check_vid_4b42() -> None:
    """Check VID 4B42 devices - might be mislabeled."""
    print("\nVID 4B42 Devices (KBDfans - but could include others):")
    print("=" * 80)
    
    ps_cmd = """
    Get-PnpDevice | Where-Object { $_.InstanceId -like '*VID_4B42*' } | 
    Select-Object FriendlyName, InstanceId, Status | Format-List
    """
    
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True
    )
    print(result.stdout)


def list_all_vids() -> None:
    """Extract and list all unique VIDs from USB devices."""
    print("\nAll Unique VIDs in USB Devices:")
    print("=" * 80)
    
    ps_cmd = """
    Get-PnpDevice -Class USB | ForEach-Object {
        if ($_.InstanceId -match 'VID_([0-9A-Fa-f]{4})') {
            $matches[1]
        }
    } | Sort-Object -Unique
    """
    
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True
    )
    
    vids = result.stdout.strip().split('\n')
    for vid in vids:
        vid = vid.strip()
        if vid:
            print(f"  VID: 0x{vid}")


def main() -> None:
    print("Deep USB Device Scan for Neewer Dongle")
    print("=" * 80)
    
    list_all_vids()
    find_unknown_devices()
    # get_all_usb_devices()  # Uncomment for full dump


if __name__ == "__main__":
    main()


"""Deep hook into Neewer DLL to discover how it communicates with the dongle."""

import frida
import sys
import subprocess
import time


def get_neewer_pid():
    """Find the Neewer Control Center process ID."""
    result = subprocess.run(
        ['powershell.exe', '-Command', "(Get-Process -Name 'Neewer Control Center' -ErrorAction SilentlyContinue).Id"],
        capture_output=True, text=True
    )
    pid_str = result.stdout.strip()
    if pid_str:
        return int(pid_str)
    return None


# Simplified hook script
HOOK_SCRIPT = """
console.log('[*] Deep hook script loaded');

// List all modules first
console.log('[*] Loaded modules:');
Process.enumerateModules().forEach(function(m) {
    if (m.name.toLowerCase().indexOf('neewer') !== -1 || 
        m.name.toLowerCase().indexOf('hid') !== -1 ||
        m.name.toLowerCase().indexOf('ble') !== -1 ||
        m.name.toLowerCase().indexOf('usb') !== -1 ||
        m.name.toLowerCase().indexOf('rf') !== -1) {
        console.log('  ' + m.name + ' @ ' + m.base);
    }
});

// Hook hid_open
var hid_open = Module.findExportByName('hidapi.dll', 'hid_open');
if (hid_open) {
    Interceptor.attach(hid_open, {
        onEnter: function(args) {
            var vid = args[0].toInt32() & 0xFFFF;
            var pid = args[1].toInt32() & 0xFFFF;
            send('[hid_open] VID=0x' + vid.toString(16) + ' PID=0x' + pid.toString(16));
        },
        onLeave: function(retval) {
            send('[hid_open] returned: ' + retval);
        }
    });
    console.log('[*] Hooked hid_open');
} else {
    console.log('[!] hid_open not found');
}

// Hook hid_write
var hid_write = Module.findExportByName('hidapi.dll', 'hid_write');
if (hid_write) {
    Interceptor.attach(hid_write, {
        onEnter: function(args) {
            var len = args[2].toInt32();
            send('[hid_write] len=' + len);
            if (len > 0 && len < 100) {
                var bytes = args[1].readByteArray(len);
                send(hexdump(bytes, {offset: 0, length: len, header: false}));
            }
        },
        onLeave: function(retval) {
            send('[hid_write] returned: ' + retval);
        }
    });
    console.log('[*] Hooked hid_write');
}

// Hook CreateFileW for device paths
var CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
if (CreateFileW) {
    Interceptor.attach(CreateFileW, {
        onEnter: function(args) {
            try {
                var path = args[0].readUtf16String();
                if (path && path.indexOf('HID') !== -1) {
                    this.path = path;
                    send('[CreateFileW] ' + path);
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.path) {
                send('[CreateFileW] handle=' + retval);
            }
        }
    });
    console.log('[*] Hooked CreateFileW');
}

// Check for BLE USB lib
var bleLib = Process.findModuleByName('BLE_USB_LIB_API_x64.dll');
if (bleLib) {
    console.log('[*] Found BLE_USB_LIB_API_x64.dll');
    
    var init_usb = Module.findExportByName('BLE_USB_LIB_API_x64.dll', 'init_usb');
    if (init_usb) {
        Interceptor.attach(init_usb, {
            onEnter: function(args) { send('[init_usb] called'); },
            onLeave: function(retval) { send('[init_usb] -> ' + retval); }
        });
        console.log('[*] Hooked init_usb');
    }
    
    var Send_Data_Func = Module.findExportByName('BLE_USB_LIB_API_x64.dll', 'Send_Data_Func');
    if (Send_Data_Func) {
        Interceptor.attach(Send_Data_Func, {
            onEnter: function(args) {
                send('[Send_Data_Func] called');
                for (var i = 0; i < 4; i++) {
                    send('  arg' + i + '=' + args[i]);
                }
            },
            onLeave: function(retval) { send('[Send_Data_Func] -> ' + retval); }
        });
        console.log('[*] Hooked Send_Data_Func');
    }
}

// Hook the RF API DLL
var rfLib = Process.findModuleByName('Set_Dongle_RF_API_x64.dll');
if (rfLib) {
    console.log('[*] Found Set_Dongle_RF_API_x64.dll at ' + rfLib.base);
}

console.log('[*] Ready! Click ON/OFF in Neewer Control Center.');
"""


def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[ERROR] {message.get('stack', message)}")


def main():
    print("Deep Hook - Discovering Neewer Dongle Communication")
    print("=" * 70)
    
    pid = get_neewer_pid()
    if not pid:
        print("[-] Neewer Control Center not running!")
        print("    Please start it first.")
        return
    
    print(f"[+] Found Neewer Control Center (PID: {pid})")
    
    try:
        session = frida.attach(pid)
        print("[+] Attached to process")
    except Exception as e:
        print(f"[-] Failed to attach: {e}")
        return
    
    script = session.create_script(HOOK_SCRIPT)
    script.on('message', on_message)
    script.load()
    
    print()
    print("=" * 70)
    print("Hooks active! Click ON/OFF button in Neewer Control Center NOW!")
    print("Press Ctrl+C to stop.")
    print("=" * 70)
    print()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDetaching...")
        session.detach()
        print("Done.")


if __name__ == "__main__":
    main()

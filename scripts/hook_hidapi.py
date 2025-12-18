"""Hook hidapi calls to discover the Neewer dongle VID/PID."""

import frida
import sys
import subprocess

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

# Hook hidapi functions to see what VID/PID the app uses
jscode = """
var hidapiModule = null;

Process.enumerateModules().forEach(function(module) {
    if (module.name.toLowerCase() === 'hidapi.dll') {
        hidapiModule = module;
        console.log('[*] Found hidapi.dll at ' + module.base);
    }
});

if (hidapiModule) {
    // Hook hid_enumerate to see what VID/PID is requested
    var hid_enumerate = Module.findExportByName('hidapi.dll', 'hid_enumerate');
    if (hid_enumerate) {
        Interceptor.attach(hid_enumerate, {
            onEnter: function(args) {
                var vid = args[0].toInt32() & 0xFFFF;
                var pid = args[1].toInt32() & 0xFFFF;
                console.log('[hid_enumerate] VID: 0x' + vid.toString(16).padStart(4, '0') + 
                            ', PID: 0x' + pid.toString(16).padStart(4, '0'));
            },
            onLeave: function(retval) {
                console.log('[hid_enumerate] returned: ' + retval);
            }
        });
        console.log('[*] Hooked hid_enumerate');
    }
    
    // Hook hid_open to see what VID/PID is opened
    var hid_open = Module.findExportByName('hidapi.dll', 'hid_open');
    if (hid_open) {
        Interceptor.attach(hid_open, {
            onEnter: function(args) {
                var vid = args[0].toInt32() & 0xFFFF;
                var pid = args[1].toInt32() & 0xFFFF;
                console.log('[hid_open] VID: 0x' + vid.toString(16).padStart(4, '0') + 
                            ', PID: 0x' + pid.toString(16).padStart(4, '0'));
            },
            onLeave: function(retval) {
                console.log('[hid_open] returned handle: ' + retval);
            }
        });
        console.log('[*] Hooked hid_open');
    }
    
    // Hook hid_open_path to see what device path is opened
    var hid_open_path = Module.findExportByName('hidapi.dll', 'hid_open_path');
    if (hid_open_path) {
        Interceptor.attach(hid_open_path, {
            onEnter: function(args) {
                var path = args[0].readCString();
                console.log('[hid_open_path] Path: ' + path);
            },
            onLeave: function(retval) {
                console.log('[hid_open_path] returned handle: ' + retval);
            }
        });
        console.log('[*] Hooked hid_open_path');
    }
    
    // Hook hid_write to see data being sent
    var hid_write = Module.findExportByName('hidapi.dll', 'hid_write');
    if (hid_write) {
        Interceptor.attach(hid_write, {
            onEnter: function(args) {
                var handle = args[0];
                var data = args[1];
                var length = args[2].toInt32();
                console.log('[hid_write] handle: ' + handle + ', length: ' + length);
                if (length > 0 && length < 256) {
                    var bytes = data.readByteArray(length);
                    console.log('[hid_write] data: ' + hexdump(bytes, {length: length, header: false}));
                }
            }
        });
        console.log('[*] Hooked hid_write');
    }
} else {
    console.log('[-] hidapi.dll not found');
}

console.log('[*] Hooks installed. Now use Neewer Control Center...');
"""

def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def main():
    print("Neewer hidapi Hook - Discovering VID/PID")
    print("=" * 60)
    print("Looking for Neewer Control Center process...")
    print()
    
    pid = get_neewer_pid()
    if not pid:
        print("[-] Neewer Control Center not found")
        print("    Please start Neewer Control Center first")
        return
    
    print(f"[+] Found Neewer Control Center (PID: {pid})")
    
    try:
        session = frida.attach(pid)
        print(f"[+] Attached to process")
    except Exception as e:
        print(f"[-] Failed to attach: {e}")
        return
    
    script = session.create_script(jscode)
    script.on('message', on_message)
    script.load()
    
    print()
    print("=" * 60)
    print("Hooks active! Click buttons in Neewer Control Center.")
    print("Press Ctrl+C to stop.")
    print("=" * 60)
    print()
    
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\nDetaching...")
        session.detach()
        print("Done.")

if __name__ == "__main__":
    main()


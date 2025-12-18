"""Frida script to hook Send_RF_DATA and capture the protocol."""

import frida
import sys
import time


PROCESS_NAME = "Neewer Control Center"
PROCESS_PID = 74716  # Fallback to PID if name doesn't work

# JavaScript code to inject into the process
HOOK_SCRIPT = """
'use strict';

// Find the Set_Dongle_RF_API_x64.dll module
const moduleName = 'Set_Dongle_RF_API_x64.dll';

// Wait for module to be loaded
function waitForModule(name, callback) {
    const module = Process.findModuleByName(name);
    if (module) {
        callback(module);
    } else {
        setTimeout(() => waitForModule(name, callback), 100);
    }
}

waitForModule(moduleName, function(module) {
    console.log('[*] Found module: ' + module.name + ' at ' + module.base);
    
    // Get exports
    const exports = module.enumerateExports();
    console.log('[*] Exports:');
    exports.forEach(exp => {
        console.log('    ' + exp.name + ' @ ' + exp.address);
    });
    
    // Hook Send_RF_DATA
    const sendRfData = module.findExportByName('Send_RF_DATA');
    if (sendRfData) {
        console.log('[*] Hooking Send_RF_DATA at ' + sendRfData);
        
        Interceptor.attach(sendRfData, {
            onEnter: function(args) {
                console.log('\\n[SEND_RF_DATA] Called!');
                
                // Try to interpret arguments
                // Common signatures:
                // int Send_RF_DATA(uint8_t* data, int length)
                // int Send_RF_DATA(int channel, uint8_t* data, int length)
                
                // Log first few args as both pointers and integers
                for (let i = 0; i < 4; i++) {
                    const argVal = args[i];
                    console.log('  arg[' + i + ']: ' + argVal + ' (as int: ' + argVal.toInt32() + ')');
                }
                
                // Try to read arg[0] as a buffer (if it's a pointer to data)
                try {
                    const ptr = args[0];
                    const possibleLen = args[1].toInt32();
                    
                    if (possibleLen > 0 && possibleLen < 1024) {
                        console.log('  Trying to read ' + possibleLen + ' bytes from arg[0]:');
                        const data = ptr.readByteArray(possibleLen);
                        console.log('  Data (hex): ' + hexdump(data, { length: possibleLen, header: false }));
                    }
                } catch (e) {
                    console.log('  Could not read arg[0] as buffer: ' + e);
                }
                
                // Also try arg[1] as buffer with arg[2] as length
                try {
                    const ptr = args[1];
                    const possibleLen = args[2].toInt32();
                    
                    if (possibleLen > 0 && possibleLen < 1024) {
                        console.log('  Trying to read ' + possibleLen + ' bytes from arg[1]:');
                        const data = ptr.readByteArray(possibleLen);
                        console.log('  Data (hex): ' + hexdump(data, { length: possibleLen, header: false }));
                    }
                } catch (e) {
                    // Silently ignore - this interpretation might be wrong
                }
                
                this.startTime = Date.now();
            },
            onLeave: function(retval) {
                const elapsed = Date.now() - this.startTime;
                console.log('  Return value: ' + retval + ' (took ' + elapsed + 'ms)');
            }
        });
    } else {
        console.log('[!] Send_RF_DATA not found!');
    }
    
    // Also hook Get_USB_State for context
    const getUsbState = module.findExportByName('Get_USB_State');
    if (getUsbState) {
        console.log('[*] Hooking Get_USB_State at ' + getUsbState);
        
        Interceptor.attach(getUsbState, {
            onEnter: function(args) {
                // Usually no args
            },
            onLeave: function(retval) {
                console.log('[GET_USB_STATE] -> ' + retval);
            }
        });
    }
});

console.log('[*] Frida hook script loaded');
console.log('[*] Waiting for ' + moduleName + '...');
console.log('[*] Now click buttons in Neewer Control Center to capture commands!');
"""


def on_message(message, data):
    """Handle messages from Frida script."""
    if message['type'] == 'send':
        print(f"[Frida] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[Frida Error] {message['stack']}")
    else:
        print(f"[Frida] {message}")


def main():
    print("Neewer Control Center Frida Hook")
    print("=" * 60)
    
    # Find the process
    print(f"Looking for process: {PROCESS_NAME}")
    
    try:
        # Attach to running process - try by name first, then by PID
        try:
            session = frida.attach(PROCESS_NAME)
            print(f"Attached to process by name!")
        except frida.ProcessNotFoundError:
            print(f"Could not find by name, trying PID {PROCESS_PID}...")
            session = frida.attach(PROCESS_PID)
            print(f"Attached to process by PID!")
        
        # Create and load the script
        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        print("\n" + "=" * 60)
        print("Hook active! Click buttons in Neewer Control Center.")
        print("Press Ctrl+C to stop.")
        print("=" * 60 + "\n")
        
        # Keep running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nDetaching...")
            session.detach()
            
    except frida.ProcessNotFoundError:
        print(f"Process '{PROCESS_NAME}' not found!")
        print("Make sure Neewer Control Center is running.")
        sys.exit(1)
    except frida.PermissionDeniedError:
        print("Permission denied! Try running as Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


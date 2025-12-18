import frida from "frida";
import * as path from "path";

// Inline agent code to trace EVERYTHING the DLL does
const AGENT_CODE = `
console.log("[*] Deep DLL trace agent loaded");

const handleToPath = new Map();
const allHandles = new Map(); // Track ALL handles

// Hook CreateFileW FIRST before anything else
const kernel32 = Process.findModuleByName("kernel32.dll");
if (kernel32) {
  const createFileW = kernel32.findExportByName("CreateFileW");
  if (createFileW) {
    Interceptor.attach(createFileW, {
      onEnter(args) {
        this.path = args[0].readUtf16String() || "";
        this.access = args[1].toUInt32();
      },
      onLeave(retval) {
        const handle = retval.toString();
        if (this.path) {
          handleToPath.set(handle, this.path);
          allHandles.set(handle, { path: this.path, access: this.access });
        }
        // Log ALL CreateFileW calls
        console.log("[CreateFileW] " + this.path + " -> " + handle + " (access=0x" + this.access.toString(16) + ")");
      },
    });
    console.log("[*] Hooked CreateFileW");
  }

  const writeFile = kernel32.findExportByName("WriteFile");
  if (writeFile) {
    Interceptor.attach(writeFile, {
      onEnter(args) {
        this.handle = args[0].toString();
        this.size = args[2].toInt32();
        this.buffer = args[1];
      },
      onLeave(retval) {
        const path = handleToPath.get(this.handle) || "UNKNOWN";
        // Log writes to unknown handles or device-like paths
        if (path === "UNKNOWN" || path.includes("\\\\\\\\?\\\\") || path.includes("HID") || path.includes("USB")) {
          console.log("[WriteFile] handle=" + this.handle + " (" + path + "), size=" + this.size + " -> " + retval);
          if (this.size > 0 && this.size <= 128) {
            const data = this.buffer.readByteArray(this.size);
            if (data) {
              console.log(hexdump(data, { offset: 0, length: this.size, header: false }));
            }
          }
        }
      },
    });
    console.log("[*] Hooked WriteFile");
  }

  const deviceIoControl = kernel32.findExportByName("DeviceIoControl");
  if (deviceIoControl) {
    Interceptor.attach(deviceIoControl, {
      onEnter(args) {
        this.handle = args[0].toString();
        this.ioctl = args[1].toUInt32();
        this.inSize = args[3].toInt32();
        this.inBuffer = args[2];
        this.outSize = args[5].toInt32();
        this.outBuffer = args[4];
      },
      onLeave(retval) {
        const path = handleToPath.get(this.handle) || "UNKNOWN";
        // Only log interesting IOCTLs (not file system ones)
        if (path === "UNKNOWN" || this.ioctl > 0x00100000) {
          console.log("[DeviceIoControl] handle=" + this.handle + " (" + path + ")");
          console.log("  IOCTL=0x" + this.ioctl.toString(16).padStart(8, "0") + " inSize=" + this.inSize + " outSize=" + this.outSize + " -> " + retval);
          if (this.inSize > 0 && this.inSize <= 128) {
            const data = this.inBuffer.readByteArray(this.inSize);
            if (data) {
              console.log("  IN:");
              console.log(hexdump(data, { offset: 0, length: this.inSize, header: false }));
            }
          }
        }
      },
    });
    console.log("[*] Hooked DeviceIoControl");
  }
}

// Hook BLE_USB_LIB functions - this is what actually talks to the device
const waitForModule = (name, callback) => {
  const check = () => {
    const mod = Process.findModuleByName(name);
    if (mod) {
      callback(mod);
    } else {
      setTimeout(check, 10);
    }
  };
  check();
};

waitForModule("BLE_USB_LIB_API_x64.dll", (mod) => {
  console.log("[*] Found BLE_USB_LIB_API_x64.dll @ " + mod.base);
  
  // List all exports
  console.log("[*] BLE_USB_LIB exports:");
  mod.enumerateExports().forEach(exp => {
    console.log("    " + exp.name + " @ " + exp.address);
  });

  const initUsb = mod.findExportByName("init_usb");
  if (initUsb) {
    Interceptor.attach(initUsb, {
      onEnter() { console.log("[init_usb] ENTER"); },
      onLeave(retval) { console.log("[init_usb] -> " + retval); },
    });
  }

  const sendDataFunc = mod.findExportByName("Send_Data_Func");
  if (sendDataFunc) {
    Interceptor.attach(sendDataFunc, {
      onEnter(args) {
        console.log("[Send_Data_Func] ENTER");
        // Log all args
        for (let i = 0; i < 4; i++) {
          console.log("  arg" + i + " = " + args[i] + " (0x" + args[i].toString(16) + ")");
        }
        // Try to read buffer from first arg
        try {
          const len = args[1].toInt32();
          if (len > 0 && len <= 64) {
            const data = args[0].readByteArray(len);
            if (data) {
              console.log("  Buffer (" + len + " bytes):");
              console.log(hexdump(data, { offset: 0, length: len, header: false }));
            }
          }
        } catch (e) {}
      },
      onLeave(retval) { console.log("[Send_Data_Func] -> " + retval); },
    });
  }
});

waitForModule("Set_Dongle_RF_API_x64.dll", (mod) => {
  console.log("[*] Found Set_Dongle_RF_API_x64.dll @ " + mod.base);

  const sendRfData = mod.findExportByName("Send_RF_DATA");
  if (sendRfData) {
    Interceptor.attach(sendRfData, {
      onEnter(args) {
        console.log("\\n========== Send_RF_DATA ENTER ==========");
        const len = args[1].toInt32();
        console.log("  buffer=" + args[0] + " len=" + len);
        if (len > 0 && len <= 64) {
          const data = args[0].readByteArray(len);
          if (data) {
            console.log(hexdump(data, { offset: 0, length: len, header: false }));
          }
        }
      },
      onLeave(retval) {
        console.log("========== Send_RF_DATA -> " + retval + " ==========\\n");
      },
    });
  }

  const getUsbState = mod.findExportByName("Get_USB_State");
  if (getUsbState) {
    Interceptor.attach(getUsbState, {
      onEnter() { console.log("[Get_USB_State] ENTER"); },
      onLeave(retval) { console.log("[Get_USB_State] -> " + retval); },
    });
  }
});

console.log("[*] Waiting for DLL calls...\\n");
`;

async function main() {
  console.log("Deep DLL Trace - Finding device communication");
  console.log("=".repeat(60));

  const scriptsDir = path.resolve(__dirname, "..", "scripts");
  const pythonScript = path.join(scriptsDir, "trigger_send.py");

  console.log("[*] Spawning Python...");
  
  const device = await frida.getLocalDevice();
  const pid = await device.spawn(["python", pythonScript], {
    cwd: scriptsDir,
    stdio: "pipe",
  });
  
  console.log(`[+] Spawned (PID: ${pid})`);

  const session = await device.attach(pid);
  const script = await session.createScript(AGENT_CODE);

  script.message.connect((message) => {
    if (message.type === "send") {
      console.log((message as frida.SendMessage).payload);
    } else if (message.type === "error") {
      console.log(`[ERROR] ${(message as frida.ErrorMessage).stack}`);
    }
  });

  await script.load();
  await device.resume(pid);
  console.log("[+] Running...\n");

  session.detached.connect(() => {
    console.log("\n[*] Done");
    process.exit(0);
  });

  await new Promise(() => {});
}

main().catch(console.error);


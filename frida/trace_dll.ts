import frida from "frida";
import { spawn } from "child_process";
import * as path from "path";

const AGENT_CODE = `
// Frida agent to trace EXACTLY what the Neewer DLL does internally

console.log("[*] Deep trace agent loaded");

// Track handles to paths
const handleToPath = new Map();

// Hook CreateFileW to track all file handles
const kernel32 = Process.findModuleByName("kernel32.dll");
if (kernel32) {
  const createFileW = kernel32.findExportByName("CreateFileW");
  if (createFileW) {
    Interceptor.attach(createFileW, {
      onEnter(args) {
        try {
          this.path = args[0].readUtf16String() || "";
        } catch {}
      },
      onLeave(retval) {
        if (this.path && retval.toInt32() !== -1) {
          const handle = retval.toString();
          handleToPath.set(handle, this.path);
          // Log ALL paths to catch the device
          console.log("[CreateFileW] " + this.path + " -> handle " + handle);
        }
      },
    });
    console.log("[*] Hooked CreateFileW");
  }

  // Hook DeviceIoControl - this is the key!
  const deviceIoControl = kernel32.findExportByName("DeviceIoControl");
  if (deviceIoControl) {
    Interceptor.attach(deviceIoControl, {
      onEnter(args) {
        this.handle = args[0].toString();
        this.ioctl = args[1].toUInt32();
        this.inSize = args[3].toInt32();
        this.inBuffer = args[2];
        
        const path = handleToPath.get(this.handle) || "unknown";
        
        // Log all DeviceIoControl calls
        console.log("[DeviceIoControl] handle=" + this.handle + " (" + path + ")");
        console.log("  IOCTL=0x" + this.ioctl.toString(16).padStart(8, "0") + ", inSize=" + this.inSize);
        
        if (this.inSize > 0 && this.inSize <= 256) {
          try {
            const data = this.inBuffer.readByteArray(this.inSize);
            if (data) {
              console.log("  Input data:");
              console.log(hexdump(data, { offset: 0, length: this.inSize, header: false }));
            }
          } catch {}
        }
      },
      onLeave(retval) {
        console.log("[DeviceIoControl] -> " + retval.toInt32());
      },
    });
    console.log("[*] Hooked DeviceIoControl");
  }

  // Hook WriteFile
  const writeFile = kernel32.findExportByName("WriteFile");
  if (writeFile) {
    Interceptor.attach(writeFile, {
      onEnter(args) {
        const handle = args[0].toString();
        const size = args[2].toInt32();
        const path = handleToPath.get(handle) || "unknown";
        
        if (size > 0 && size <= 64) {
          console.log("[WriteFile] handle=" + handle + " (" + path + "), size=" + size);
          try {
            const data = args[1].readByteArray(size);
            if (data) {
              console.log(hexdump(data, { offset: 0, length: size, header: false }));
            }
          } catch {}
        }
      },
      onLeave(retval) {
        console.log("[WriteFile] -> " + retval.toInt32());
      },
    });
    console.log("[*] Hooked WriteFile");
  }
}

// Hook the RF DLL when it loads
function hookRfDll() {
  const rfLib = Process.findModuleByName("Set_Dongle_RF_API_x64.dll");
  if (rfLib) {
    console.log("[*] Found Set_Dongle_RF_API_x64.dll @ " + rfLib.base);

    const sendRfData = rfLib.findExportByName("Send_RF_DATA");
    if (sendRfData) {
      Interceptor.attach(sendRfData, {
        onEnter(args) {
          console.log("\\n========== Send_RF_DATA CALLED ==========");
          const len = args[1].toInt32();
          console.log("  buffer=" + args[0] + ", len=" + len);
          if (len > 0 && len <= 64) {
            const data = args[0].readByteArray(len);
            if (data) {
              console.log("  Packet data:");
              console.log(hexdump(data, { offset: 0, length: len, header: false }));
            }
          }
        },
        onLeave(retval) {
          console.log("========== Send_RF_DATA RETURNED " + retval + " ==========\\n");
        },
      });
      console.log("[*] Hooked Send_RF_DATA");
    }

    const getUsbState = rfLib.findExportByName("Get_USB_State");
    if (getUsbState) {
      Interceptor.attach(getUsbState, {
        onEnter() {
          console.log("[Get_USB_State] called");
        },
        onLeave(retval) {
          console.log("[Get_USB_State] -> " + retval);
        },
      });
      console.log("[*] Hooked Get_USB_State");
    }
    return true;
  }
  return false;
}

// Hook HID.DLL functions
const hidDll = Process.findModuleByName("HID.DLL");
if (hidDll) {
  console.log("[*] Found HID.DLL @ " + hidDll.base);

  const hidD_SetOutputReport = hidDll.findExportByName("HidD_SetOutputReport");
  if (hidD_SetOutputReport) {
    Interceptor.attach(hidD_SetOutputReport, {
      onEnter(args) {
        const handle = args[0].toString();
        const size = args[2].toInt32();
        const path = handleToPath.get(handle) || "unknown";
        
        console.log("[HidD_SetOutputReport] handle=" + handle + " (" + path + "), size=" + size);
        if (size > 0 && size <= 64) {
          try {
            const data = args[1].readByteArray(size);
            if (data) {
              console.log(hexdump(data, { offset: 0, length: size, header: false }));
            }
          } catch {}
        }
      },
      onLeave(retval) {
        console.log("[HidD_SetOutputReport] -> " + retval);
      },
    });
    console.log("[*] Hooked HidD_SetOutputReport");
  }
}

// Try to hook RF DLL now or when it loads
if (!hookRfDll()) {
  console.log("[*] RF DLL not loaded yet, waiting...");
}

console.log("\\n[*] Ready! Waiting for DLL calls...\\n");
`;

async function main() {
  console.log("Neewer DLL Deep Trace");
  console.log("=".repeat(60));

  // Spawn Python with our trigger script
  const scriptsDir = path.resolve(__dirname, "..", "scripts");
  const pythonScript = path.join(scriptsDir, "trigger_send.py");

  console.log("[*] Spawning Python process...");
  
  const device = await frida.getLocalDevice();
  
  // Spawn Python and immediately attach
  const pid = await device.spawn(["python", pythonScript], {
    cwd: scriptsDir,
    stdio: "pipe",
  });
  
  console.log(`[+] Spawned Python process (PID: ${pid})`);

  const session = await device.attach(pid);
  console.log("[+] Attached to process");

  const script = await session.createScript(AGENT_CODE);

  script.message.connect((message) => {
    if (message.type === "send") {
      console.log((message as frida.SendMessage).payload);
    } else if (message.type === "error") {
      console.log(`[ERROR] ${(message as frida.ErrorMessage).stack}`);
    }
  });

  await script.load();
  console.log("[+] Agent loaded");

  // Resume the process
  await device.resume(pid);
  console.log("[+] Process resumed\n");

  // Wait for process to exit
  session.detached.connect(() => {
    console.log("\n[*] Process exited");
    process.exit(0);
  });

  // Keep running
  await new Promise(() => {});
}

main().catch((e) => {
  console.error("Error:", e);
  process.exit(1);
});


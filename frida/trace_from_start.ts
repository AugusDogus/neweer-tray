import frida from "frida";
import * as path from "path";

// Agent that hooks LoadLibrary to catch DLL initialization
const AGENT_CODE = `
console.log("[*] Early hook agent - catching DLL load");

const handleToPath = new Map();

// Hook CreateFileW IMMEDIATELY
const kernel32 = Process.findModuleByName("kernel32.dll");

const createFileW = kernel32.findExportByName("CreateFileW");
Interceptor.attach(createFileW, {
  onEnter(args) {
    this.path = args[0].readUtf16String() || "";
    this.access = args[1].toUInt32();
  },
  onLeave(retval) {
    const handle = retval.toString();
    handleToPath.set(handle, this.path);
    // Log device paths
    if (this.path && (this.path.includes("\\\\\\\\?\\\\") || this.path.includes("HID") || this.path.includes("USB") || this.path.includes("vid_") || this.path.includes("VID_"))) {
      console.log("[CreateFileW] DEVICE: " + this.path);
      console.log("  -> handle " + handle + " (access=0x" + this.access.toString(16) + ")");
    }
  },
});
console.log("[*] Hooked CreateFileW");

const writeFile = kernel32.findExportByName("WriteFile");
Interceptor.attach(writeFile, {
  onEnter(args) {
    this.handle = args[0].toString();
    this.size = args[2].toInt32();
    this.buffer = args[1];
  },
  onLeave(retval) {
    const path = handleToPath.get(this.handle) || "UNKNOWN";
    // Log writes that look like device communication (64 bytes, starts with our header)
    if (this.size === 64) {
      const data = this.buffer.readByteArray(this.size);
      if (data) {
        const bytes = new Uint8Array(data);
        // Check if it contains our command signature (77 58)
        for (let i = 0; i < bytes.length - 1; i++) {
          if (bytes[i] === 0x77 && bytes[i+1] === 0x58) {
            console.log("\\n[WriteFile] FOUND COMMAND at offset " + i);
            console.log("  handle=" + this.handle + " (" + path + ")");
            console.log("  Header bytes: " + Array.from(bytes.slice(0, i)).map(b => b.toString(16).padStart(2, '0')).join(' '));
            console.log(hexdump(data, { offset: 0, length: this.size, header: false }));
            break;
          }
        }
      }
    }
  },
});
console.log("[*] Hooked WriteFile");

// Hook DeviceIoControl for SetupAPI calls
const deviceIoControl = kernel32.findExportByName("DeviceIoControl");
Interceptor.attach(deviceIoControl, {
  onEnter(args) {
    this.handle = args[0].toString();
    this.ioctl = args[1].toUInt32();
    this.inSize = args[3].toInt32();
    this.inBuffer = args[2];
  },
  onLeave(retval) {
    const path = handleToPath.get(this.handle) || "UNKNOWN";
    // Log SetupAPI IOCTLs (0x00470xxx range)
    if ((this.ioctl & 0xFFFF0000) === 0x00470000) {
      console.log("[DeviceIoControl] IOCTL=0x" + this.ioctl.toString(16) + " handle=" + this.handle + " (" + path + ") -> " + retval);
    }
  },
});
console.log("[*] Hooked DeviceIoControl");

// Hook SetupDiGetDeviceInterfaceDetailW to see device paths
const setupapi = Process.findModuleByName("setupapi.dll");
if (setupapi) {
  const getDetail = setupapi.findExportByName("SetupDiGetDeviceInterfaceDetailW");
  if (getDetail) {
    Interceptor.attach(getDetail, {
      onEnter(args) {
        this.detailData = args[2];
        this.detailSize = args[3].toInt32();
      },
      onLeave(retval) {
        if (retval.toInt32() !== 0 && this.detailData && !this.detailData.isNull()) {
          try {
            // cbSize is first DWORD, then DevicePath starts at offset 4
            const devicePath = this.detailData.add(4).readUtf16String();
            if (devicePath && (devicePath.includes("vid_") || devicePath.includes("VID_"))) {
              console.log("[SetupDiGetDeviceInterfaceDetailW] " + devicePath);
            }
          } catch (e) {}
        }
      },
    });
    console.log("[*] Hooked SetupDiGetDeviceInterfaceDetailW");
  }
}

// Watch for DLL loads
const loadLibraryW = kernel32.findExportByName("LoadLibraryW");
Interceptor.attach(loadLibraryW, {
  onEnter(args) {
    this.name = args[0].readUtf16String();
  },
  onLeave(retval) {
    if (this.name && (this.name.includes("BLE_USB") || this.name.includes("Set_Dongle") || this.name.includes("hidapi"))) {
      console.log("[LoadLibraryW] " + this.name + " -> " + retval);
    }
  },
});
console.log("[*] Hooked LoadLibraryW");

console.log("[*] Ready - waiting for DLL activity...\\n");
`;

async function main() {
  console.log("Deep Trace - Catching device open from DLL load");
  console.log("=".repeat(60));

  const scriptsDir = path.resolve(__dirname, "..", "scripts");
  const pythonScript = path.join(scriptsDir, "trigger_send.py");

  const device = await frida.getLocalDevice();
  
  // Spawn with hooks ready before DLL loads
  console.log("[*] Spawning Python (paused)...");
  const pid = await device.spawn(["python", pythonScript], {
    cwd: scriptsDir,
    stdio: "pipe",
  });
  
  console.log(`[+] Spawned PID ${pid}, attaching...`);
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
  console.log("[+] Hooks installed, resuming...\n");
  await device.resume(pid);

  session.detached.connect(() => {
    console.log("\n[*] Process exited");
    process.exit(0);
  });

  await new Promise(() => {});
}

main().catch(console.error);


import frida from "frida";
import * as path from "path";
import * as fs from "fs";

const LOG_PATH = path.join(__dirname, "..", "debug.log");

function writeLog(hypothesisId: string, location: string, message: string, data: Record<string, unknown>) {
  const entry = JSON.stringify({
    location,
    message,
    data,
    timestamp: Date.now(),
    sessionId: "debug-session",
    hypothesisId
  }) + "\n";
  fs.appendFileSync(LOG_PATH, entry);
}

// Agent that hooks ALL possible file/device open methods
const AGENT_CODE = `
// Use Frida's send() to communicate with host
function log(hypothesisId, location, message, data) {
  send({ type: 'log', hypothesisId, location, message, data });
}

log("INIT", "agent:1", "Agent loaded", {});

const kernel32 = Process.findModuleByName("kernel32.dll");
const ntdll = Process.findModuleByName("ntdll.dll");

// #region agent log - Hypothesis B: Hook NtCreateFile (lower-level)
const ntCreateFile = ntdll.findExportByName("NtCreateFile");
if (ntCreateFile) {
  Interceptor.attach(ntCreateFile, {
    onEnter(args) {
      // arg[0] = FileHandle (output), arg[2] = ObjectAttributes
      this.handlePtr = args[0];
    },
    onLeave(retval) {
      // Only log successful calls
      if (retval.toInt32() === 0) {
        try {
          const handle = this.handlePtr.readPointer().toString();
          log("B", "NtCreateFile", "NtCreateFile success", { handle: handle });
        } catch(e) {}
      }
    },
  });
  log("INIT", "agent:hook", "Hooked NtCreateFile", {});
}
// #endregion

// #region agent log - Hypothesis E: Hook CreateFileA (ANSI version)
const createFileA = kernel32.findExportByName("CreateFileA");
if (createFileA) {
  Interceptor.attach(createFileA, {
    onEnter(args) {
      this.path = args[0].readCString() || "";
    },
    onLeave(retval) {
      const h = retval.toInt32();
      if (h !== -1 && this.path && (this.path.includes("HID") || this.path.includes("USB") || this.path.includes("vid_") || this.path.includes("\\\\\\\\?\\\\"))) {
        log("E", "CreateFileA", "CreateFileA device open", { path: this.path, handle: retval.toString() });
      }
    },
  });
  log("INIT", "agent:hook", "Hooked CreateFileA", {});
}
// #endregion

// #region agent log - Hook CreateFileW with more detail
const createFileW = kernel32.findExportByName("CreateFileW");
Interceptor.attach(createFileW, {
  onEnter(args) {
    this.path = args[0].readUtf16String() || "";
  },
  onLeave(retval) {
    const h = retval.toInt32();
    if (h !== -1 && this.path && (this.path.includes("HID") || this.path.includes("USB") || this.path.includes("vid_") || this.path.includes("VID_") || this.path.includes("\\\\\\\\?\\\\"))) {
      log("C", "CreateFileW", "CreateFileW device open", { path: this.path, handle: retval.toString() });
    }
  },
});
log("INIT", "agent:hook", "Hooked CreateFileW", {});
// #endregion

// #region agent log - Hypothesis C: Hook LoadLibraryW to see DLL load timing
const loadLibraryW = kernel32.findExportByName("LoadLibraryW");
Interceptor.attach(loadLibraryW, {
  onEnter(args) {
    this.name = args[0].readUtf16String() || "";
    if (this.name.includes("BLE_USB") || this.name.includes("Set_Dongle")) {
      log("C", "LoadLibraryW:enter", "DLL loading START", { name: this.name });
    }
  },
  onLeave(retval) {
    if (this.name && (this.name.includes("BLE_USB") || this.name.includes("Set_Dongle"))) {
      log("C", "LoadLibraryW:leave", "DLL loading END", { name: this.name, base: retval.toString() });
    }
  },
});
log("INIT", "agent:hook", "Hooked LoadLibraryW", {});
// #endregion

// #region agent log - Track WriteFile to see which handle is used
const writeFile = kernel32.findExportByName("WriteFile");
Interceptor.attach(writeFile, {
  onEnter(args) {
    this.handle = args[0].toString();
    this.size = args[2].toInt32();
    this.buffer = args[1];
  },
  onLeave(retval) {
    if (this.size === 64) {
      try {
        const data = this.buffer.readByteArray(Math.min(this.size, 16));
        if (data) {
          const bytes = new Uint8Array(data);
          for (let i = 0; i < bytes.length - 1; i++) {
            if (bytes[i] === 0x77 && bytes[i+1] === 0x58) {
              log("WRITE", "WriteFile", "Command sent", { 
                handle: this.handle,
                offset: i,
                header: Array.from(bytes.slice(0, i)).map(b => b.toString(16).padStart(2, '0')).join(' ')
              });
              break;
            }
          }
        }
      } catch(e) {}
    }
  },
});
log("INIT", "agent:hook", "Hooked WriteFile", {});
// #endregion

log("INIT", "agent:ready", "All hooks installed", {});
`;

async function main() {
  console.log("Tracing ALL device open methods");
  console.log("=".repeat(60));

  // Clear log file
  try { fs.unlinkSync(LOG_PATH); } catch {}

  const scriptsDir = path.resolve(__dirname, "..", "scripts");
  const pythonScript = path.join(scriptsDir, "trigger_send.py");

  const device = await frida.getLocalDevice();
  
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
      const payload = (message as frida.SendMessage).payload;
      if (payload.type === "log") {
        writeLog(payload.hypothesisId, payload.location, payload.message, payload.data);
        console.log(`[${payload.hypothesisId}] ${payload.message}: ${JSON.stringify(payload.data)}`);
      }
    } else if (message.type === "error") {
      console.log(`[ERROR] ${(message as frida.ErrorMessage).stack}`);
    }
  });

  await script.load();
  console.log("[+] Hooks installed, resuming...\n");
  await device.resume(pid);

  session.detached.connect(() => {
    console.log("\n[*] Process exited");
    console.log(`[*] Logs written to ${LOG_PATH}`);
    process.exit(0);
  });

  await new Promise(() => {});
}

main().catch(console.error);

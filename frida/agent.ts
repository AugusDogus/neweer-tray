// Frida agent to trace EXACTLY what the Neewer DLL does internally

console.log("[*] Deep trace agent loaded");

// Track handles to paths
const handleToPath = new Map<string, string>();

// Hook CreateFileW to track all file handles
const kernel32 = Process.findModuleByName("kernel32.dll");
if (kernel32) {
  const createFileW = kernel32.findExportByName("CreateFileW");
  if (createFileW) {
    Interceptor.attach(createFileW, {
      onEnter(this: { path?: string }, args) {
        try {
          this.path = args[0].readUtf16String() || "";
        } catch {}
      },
      onLeave(this: { path?: string }, retval) {
        if (this.path && retval.toInt32() !== -1) {
          const handle = retval.toString();
          handleToPath.set(handle, this.path);
          // Only log device paths
          if (this.path.startsWith("\\\\")) {
            console.log(`[CreateFileW] ${this.path} -> handle ${handle}`);
          }
        }
      },
    });
    console.log("[*] Hooked CreateFileW");
  }

  // Hook DeviceIoControl - this is the key!
  const deviceIoControl = kernel32.findExportByName("DeviceIoControl");
  if (deviceIoControl) {
    Interceptor.attach(deviceIoControl, {
      onEnter(this: { handle: string; ioctl: number; inSize: number; inBuffer: NativePointer }, args) {
        this.handle = args[0].toString();
        this.ioctl = args[1].toUInt32();
        this.inSize = args[3].toInt32();
        this.inBuffer = args[2];
        
        const path = handleToPath.get(this.handle) || "unknown";
        
        // Log all DeviceIoControl calls
        console.log(`[DeviceIoControl] handle=${this.handle} (${path})`);
        console.log(`  IOCTL=0x${this.ioctl.toString(16).padStart(8, "0")}, inSize=${this.inSize}`);
        
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
      onLeave(this: { handle: string; ioctl: number }, retval) {
        console.log(`[DeviceIoControl] -> ${retval.toInt32()}`);
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
          console.log(`[WriteFile] handle=${handle} (${path}), size=${size}`);
          try {
            const data = args[1].readByteArray(size);
            if (data) {
              console.log(hexdump(data, { offset: 0, length: size, header: false }));
            }
          } catch {}
        }
      },
      onLeave(retval) {
        console.log(`[WriteFile] -> ${retval.toInt32()}`);
      },
    });
    console.log("[*] Hooked WriteFile");
  }
}

// Hook the RF DLL
const rfLib = Process.findModuleByName("Set_Dongle_RF_API_x64.dll");
if (rfLib) {
  console.log(`[*] Found Set_Dongle_RF_API_x64.dll @ ${rfLib.base}`);

  const sendRfData = rfLib.findExportByName("Send_RF_DATA");
  if (sendRfData) {
    Interceptor.attach(sendRfData, {
      onEnter(args) {
        console.log("\n========== Send_RF_DATA CALLED ==========");
        const len = args[1].toInt32();
        console.log(`  buffer=${args[0]}, len=${len}`);
        if (len > 0 && len <= 64) {
          const data = args[0].readByteArray(len);
          if (data) {
            console.log("  Packet data:");
            console.log(hexdump(data, { offset: 0, length: len, header: false }));
          }
        }
      },
      onLeave(retval) {
        console.log(`========== Send_RF_DATA RETURNED ${retval} ==========\n`);
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
        console.log(`[Get_USB_State] -> ${retval}`);
      },
    });
    console.log("[*] Hooked Get_USB_State");
  }
}

// Hook BLE USB lib
const bleLib = Process.findModuleByName("BLE_USB_LIB_API_x64.dll");
if (bleLib) {
  console.log(`[*] Found BLE_USB_LIB_API_x64.dll @ ${bleLib.base}`);

  const initUsb = bleLib.findExportByName("init_usb");
  if (initUsb) {
    Interceptor.attach(initUsb, {
      onEnter() {
        console.log("[init_usb] called");
      },
      onLeave(retval) {
        console.log(`[init_usb] -> ${retval}`);
      },
    });
    console.log("[*] Hooked init_usb");
  }

  const sendDataFunc = bleLib.findExportByName("Send_Data_Func");
  if (sendDataFunc) {
    Interceptor.attach(sendDataFunc, {
      onEnter(args) {
        console.log("[Send_Data_Func] called");
        // Log all arguments
        for (let i = 0; i < 6; i++) {
          try {
            console.log(`  arg${i}=${args[i]} (int: ${args[i].toInt32()})`);
          } catch {
            console.log(`  arg${i}=${args[i]}`);
          }
        }
        // Try to read buffer from arg0
        try {
          const len = args[1].toInt32();
          if (len > 0 && len <= 64) {
            const data = args[0].readByteArray(len);
            if (data) {
              console.log("  Buffer data:");
              console.log(hexdump(data, { offset: 0, length: len, header: false }));
            }
          }
        } catch {}
      },
      onLeave(retval) {
        console.log(`[Send_Data_Func] -> ${retval}`);
      },
    });
    console.log("[*] Hooked Send_Data_Func");
  }

  const readUsbData = bleLib.findExportByName("Read_Usb_data");
  if (readUsbData) {
    Interceptor.attach(readUsbData, {
      onEnter(args) {
        console.log("[Read_Usb_data] called");
      },
      onLeave(retval) {
        console.log(`[Read_Usb_data] -> ${retval}`);
      },
    });
    console.log("[*] Hooked Read_Usb_data");
  }
}

// Hook HID.DLL functions
const hidDll = Process.findModuleByName("HID.DLL");
if (hidDll) {
  console.log(`[*] Found HID.DLL @ ${hidDll.base}`);

  const hidD_SetOutputReport = hidDll.findExportByName("HidD_SetOutputReport");
  if (hidD_SetOutputReport) {
    Interceptor.attach(hidD_SetOutputReport, {
      onEnter(args) {
        const handle = args[0].toString();
        const size = args[2].toInt32();
        const path = handleToPath.get(handle) || "unknown";
        
        console.log(`[HidD_SetOutputReport] handle=${handle} (${path}), size=${size}`);
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
        console.log(`[HidD_SetOutputReport] -> ${retval}`);
      },
    });
    console.log("[*] Hooked HidD_SetOutputReport");
  }
}

// Hook hidapi.dll functions
const hidapiModule = Process.findModuleByName("hidapi.dll");
if (hidapiModule) {
  console.log(`[*] Found hidapi.dll @ ${hidapiModule.base}`);

  const hidWrite = hidapiModule.findExportByName("hid_write");
  if (hidWrite) {
    Interceptor.attach(hidWrite, {
      onEnter(args) {
        const len = args[2].toInt32();
        console.log(`[hid_write] device=${args[0]}, len=${len}`);
        if (len > 0 && len <= 64) {
          try {
            const data = args[1].readByteArray(len);
            if (data) {
              console.log(hexdump(data, { offset: 0, length: len, header: false }));
            }
          } catch {}
        }
      },
      onLeave(retval) {
        console.log(`[hid_write] -> ${retval}`);
      },
    });
    console.log("[*] Hooked hid_write");
  }

  const hidOpen = hidapiModule.findExportByName("hid_open");
  if (hidOpen) {
    Interceptor.attach(hidOpen, {
      onEnter(args) {
        const vid = args[0].toInt32() & 0xffff;
        const pid = args[1].toInt32() & 0xffff;
        console.log(`[hid_open] VID=0x${vid.toString(16).padStart(4, "0")} PID=0x${pid.toString(16).padStart(4, "0")}`);
      },
      onLeave(retval) {
        console.log(`[hid_open] -> ${retval}`);
      },
    });
    console.log("[*] Hooked hid_open");
  }
}

console.log("\n[*] Ready! Now trigger Send_RF_DATA from Python...\n");

# Neewer Tray

A minimal Neewer light controller.

- `src/` contains the Windows tray app written in Zig
- `cosmic-applet/` contains the native COSMIC panel applet for Linux written in Rust

## Usage

1. Ensure the Neewer 2.4GHz dongle is plugged in
2. Run `neewer-tray.exe`
3. Click the lightbulb icon in the system tray to toggle lights
4. Right-click for menu with Exit option

## Linux COSMIC applet

If you are using COSMIC on Linux, the Rust applet lives in `cosmic-applet/`.

```bash
cd cosmic-applet
cargo build
```

## Building the Windows app

Requires [Zig](https://ziglang.org/) 0.15+.

```bash
zig build
```

The Zig build is for the Windows tray app. The executable will be at `zig-out/bin/neewer-tray.exe`.

## How it works

This app communicates directly with the Neewer 2.4GHz USB dongle (VID `0x0581`, PID `0x011D`) using the Windows HID API. No external DLLs or Neewer Control Center installation required.

The protocol was reverse-engineered using Frida to hook the `Send_RF_DATA` function in Neewer's `Set_Dongle_RF_API_x64.dll`.

## Scripts

The `scripts/` directory contains Python utilities used during reverse engineering:

- `frida_hook.py` - Hook `Send_RF_DATA` calls to capture protocol
- `analyze_protocol.py` - Analyze captured packets
- `neewer_control.py` - Simple Python script to toggle lights
- `create_icon.py` - Generate the tray icon from Segoe MDL2 Assets font

## License

MIT


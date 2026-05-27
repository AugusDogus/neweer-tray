# Neewer Tray

A minimal Neewer light controller.

- `src/` contains the Windows tray app written in Zig
- `cosmic-applet/` contains the Linux Rust apps:
  - the native COSMIC panel applet
  - a GNOME-compatible StatusNotifier/AppIndicator tray binary

## Windows Usage

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

## Linux GNOME tray

GNOME does not show tray icons by default. You need the AppIndicator/KStatusNotifierItem shell extension enabled for the tray icon to appear.

- Ubuntu: install `gnome-shell-extension-appindicator`
- Fedora: install `gnome-extensions-appindicator`

Then build and run the GNOME tray binary:

```bash
cd cosmic-applet
cargo build --bin neewer-gnome-tray
./target/debug/neewer-gnome-tray
```

Left-click the tray icon to toggle the lights. Right-click it for the menu and Quit action.

## Linux GNOME quick settings

If you want the control in GNOME's quick settings menu instead of the tray, use the shell extension in `gnome-extension/`.

Build the one-shot helper binary and install it to a stable path:

```bash
cd cosmic-applet
cargo build --release --bin neewer-toggle
install -m 755 target/release/neewer-toggle ~/.local/bin/neewer-toggle
```

Then install the extension into `~/.local/share/gnome-shell/extensions/neewer-quick-toggle@augie.dev/` and enable it with `gnome-extensions enable neewer-quick-toggle@augie.dev`.

For autostart, use a stable install path instead of running from `target/` directly:

```bash
cd cosmic-applet
cargo build --release --bin neewer-gnome-tray
install -m 755 target/release/neewer-gnome-tray ~/.local/bin/neewer-gnome-tray
```

Then create `~/.config/autostart/neewer-gnome-tray.desktop`:

```ini
[Desktop Entry]
Type=Application
Version=1.0
Name=Neewer Tray
Exec=/home/your-user/.local/bin/neewer-gnome-tray
Icon=dev.augie.CosmicAppletNeewer-symbolic
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
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


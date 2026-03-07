# COSMIC Applet

This subproject contains a native COSMIC panel applet for Linux.

## Behavior

- Shows a lightbulb-style brightness icon in the COSMIC panel
- Toggles all paired Neewer lights when the icon is clicked
- Talks to the Neewer 2.4GHz USB dongle through `hidapi`

## Build

```bash
cargo build
```

## Install

Build the binary, then place the binary on your `PATH` and install the desktop file:

```bash
install -Dm755 target/debug/cosmic-applet-neewer ~/.local/bin/cosmic-applet-neewer
install -Dm644 data/dev.augie.CosmicAppletNeewer.desktop ~/.local/share/applications/dev.augie.CosmicAppletNeewer.desktop
install -Dm644 data/icons/hicolor/scalable/status/dev.augie.CosmicAppletNeewer-symbolic.svg ~/.local/share/icons/hicolor/scalable/status/dev.augie.CosmicAppletNeewer-symbolic.svg
install -Dm644 data/icons/hicolor/scalable/status/dev.augie.CosmicAppletNeewer-active-symbolic.svg ~/.local/share/icons/hicolor/scalable/status/dev.augie.CosmicAppletNeewer-active-symbolic.svg
```

After that, add `Neewer Lights` to the COSMIC panel from COSMIC Settings.

## Udev access

The Neewer dongle shows up as a `hidraw` device. If it is owned by `root`, install the bundled udev rule so your logged-in user can access it:

```bash
sudo install -Dm644 data/70-neewer-dongle.rules /etc/udev/rules.d/70-neewer-dongle.rules
sudo udevadm control --reload-rules
sudo udevadm trigger --subsystem-match=hidraw
```

Then unplug and replug the dongle, or log out and back in.

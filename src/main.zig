const std = @import("std");
const windows = std.os.windows;
const HWND = windows.HWND;
const HINSTANCE = windows.HINSTANCE;
const WPARAM = windows.WPARAM;
const LPARAM = windows.LPARAM;
const LRESULT = windows.LRESULT;
const UINT = windows.UINT;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;
const WCHAR = windows.WCHAR;
const GUID = windows.GUID;
const HANDLE = windows.HANDLE;

// Windows API types and functions
const HICON = *opaque {};
const HMENU = *opaque {};
const HDEVINFO = *opaque {};
const POINT = extern struct { x: i32, y: i32 };

// Neewer dongle identifiers
const NEEWER_VID: u16 = 0x0581;
const NEEWER_PID: u16 = 0x011D;

// Shell API structures
const NOTIFYICONDATAW = extern struct {
    cbSize: DWORD,
    hWnd: ?HWND,
    uID: UINT,
    uFlags: UINT,
    uCallbackMessage: UINT,
    hIcon: ?HICON,
    szTip: [128]WCHAR,
    dwState: DWORD,
    dwStateMask: DWORD,
    szInfo: [256]WCHAR,
    uVersion: UINT,
    szInfoTitle: [64]WCHAR,
    dwInfoFlags: DWORD,
    guidItem: GUID,
    hBalloonIcon: ?HICON,
};

const WNDCLASSEXW = extern struct {
    cbSize: UINT = @sizeOf(WNDCLASSEXW),
    style: UINT = 0,
    lpfnWndProc: *const fn (HWND, UINT, WPARAM, LPARAM) callconv(windows.WINAPI) LRESULT,
    cbClsExtra: i32 = 0,
    cbWndExtra: i32 = 0,
    hInstance: ?HINSTANCE,
    hIcon: ?HICON = null,
    hCursor: ?HICON = null,
    hbrBackground: ?*opaque {} = null,
    lpszMenuName: ?[*:0]const WCHAR = null,
    lpszClassName: [*:0]const WCHAR,
    hIconSm: ?HICON = null,
};

const MSG = extern struct {
    hwnd: ?HWND,
    message: UINT,
    wParam: WPARAM,
    lParam: LPARAM,
    time: DWORD,
    pt: POINT,
};

const SP_DEVICE_INTERFACE_DATA = extern struct {
    cbSize: DWORD,
    InterfaceClassGuid: GUID,
    Flags: DWORD,
    Reserved: usize,
};

// Constants
const WM_APP: UINT = 0x8000;
const WM_TRAYICON: UINT = WM_APP + 1;
const WM_CREATE: UINT = 0x0001;
const WM_DESTROY: UINT = 0x0002;
const WM_COMMAND: UINT = 0x0111;
const WM_LBUTTONUP: UINT = 0x0202;
const WM_RBUTTONUP: UINT = 0x0205;

const NIF_MESSAGE: UINT = 0x00000001;
const NIF_ICON: UINT = 0x00000002;
const NIF_TIP: UINT = 0x00000004;
const NIM_ADD: DWORD = 0x00000000;
const NIM_DELETE: DWORD = 0x00000002;

const IDI_APPLICATION: usize = 32512;
const IMAGE_ICON: UINT = 1;
const LR_DEFAULTSIZE: UINT = 0x00000040;
const IDI_LIGHTBULB: usize = 1;
const TPM_RIGHTBUTTON: UINT = 0x0002;
const TPM_BOTTOMALIGN: UINT = 0x0020;
const MF_STRING: UINT = 0x00000000;
const MF_SEPARATOR: UINT = 0x00000800;

const CW_USEDEFAULT: i32 = @bitCast(@as(u32, 0x80000000));
const SW_HIDE: i32 = 0;

const TRAY_UID: UINT = 1001;
const IDM_TOGGLE: UINT = 2001;
const IDM_EXIT: UINT = 2002;

const GENERIC_READ: DWORD = 0x80000000;
const GENERIC_WRITE: DWORD = 0x40000000;
const FILE_SHARE_READ: DWORD = 0x00000001;
const FILE_SHARE_WRITE: DWORD = 0x00000002;
const OPEN_EXISTING: DWORD = 3;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

const DIGCF_PRESENT: DWORD = 0x00000002;
const DIGCF_DEVICEINTERFACE: DWORD = 0x00000010;

// HID GUID: {4D1E55B2-F16F-11CF-88CB-001111000030}
const GUID_DEVINTERFACE_HID = GUID{
    .Data1 = 0x4D1E55B2,
    .Data2 = 0xF16F,
    .Data3 = 0x11CF,
    .Data4 = .{ 0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 },
};

// Windows API imports
extern "user32" fn RegisterClassExW(*const WNDCLASSEXW) callconv(windows.WINAPI) u16;
extern "user32" fn CreateWindowExW(DWORD, [*:0]const WCHAR, [*:0]const WCHAR, DWORD, i32, i32, i32, i32, ?HWND, ?HMENU, ?HINSTANCE, ?*anyopaque) callconv(windows.WINAPI) ?HWND;
extern "user32" fn ShowWindow(?HWND, i32) callconv(windows.WINAPI) BOOL;
extern "user32" fn GetMessageW(*MSG, ?HWND, UINT, UINT) callconv(windows.WINAPI) BOOL;
extern "user32" fn TranslateMessage(*const MSG) callconv(windows.WINAPI) BOOL;
extern "user32" fn DispatchMessageW(*const MSG) callconv(windows.WINAPI) LRESULT;
extern "user32" fn DefWindowProcW(?HWND, UINT, WPARAM, LPARAM) callconv(windows.WINAPI) LRESULT;
extern "user32" fn PostQuitMessage(i32) callconv(windows.WINAPI) void;
extern "user32" fn LoadIconW(?HINSTANCE, usize) callconv(windows.WINAPI) ?HICON;
extern "user32" fn LoadImageW(?HINSTANCE, usize, UINT, i32, i32, UINT) callconv(windows.WINAPI) ?HICON;
extern "user32" fn DestroyWindow(?HWND) callconv(windows.WINAPI) BOOL;
extern "user32" fn CreatePopupMenu() callconv(windows.WINAPI) ?HMENU;
extern "user32" fn AppendMenuW(?HMENU, UINT, usize, ?[*:0]const WCHAR) callconv(windows.WINAPI) BOOL;
extern "user32" fn TrackPopupMenu(?HMENU, UINT, i32, i32, i32, ?HWND, ?*const anyopaque) callconv(windows.WINAPI) BOOL;
extern "user32" fn DestroyMenu(?HMENU) callconv(windows.WINAPI) BOOL;
extern "user32" fn GetCursorPos(*POINT) callconv(windows.WINAPI) BOOL;
extern "user32" fn SetForegroundWindow(?HWND) callconv(windows.WINAPI) BOOL;
extern "user32" fn MessageBoxW(?HWND, [*:0]const WCHAR, [*:0]const WCHAR, UINT) callconv(windows.WINAPI) i32;
extern "shell32" fn Shell_NotifyIconW(DWORD, *NOTIFYICONDATAW) callconv(windows.WINAPI) BOOL;

// SetupAPI imports
extern "setupapi" fn SetupDiGetClassDevsW(?*const GUID, ?[*:0]const WCHAR, ?HWND, DWORD) callconv(windows.WINAPI) ?HDEVINFO;
extern "setupapi" fn SetupDiEnumDeviceInterfaces(?HDEVINFO, ?*anyopaque, *const GUID, DWORD, *SP_DEVICE_INTERFACE_DATA) callconv(windows.WINAPI) BOOL;
extern "setupapi" fn SetupDiGetDeviceInterfaceDetailW(?HDEVINFO, *SP_DEVICE_INTERFACE_DATA, ?*anyopaque, DWORD, ?*DWORD, ?*anyopaque) callconv(windows.WINAPI) BOOL;
extern "setupapi" fn SetupDiDestroyDeviceInfoList(?HDEVINFO) callconv(windows.WINAPI) BOOL;

// Kernel32 imports
extern "kernel32" fn CreateFileW([*:0]const WCHAR, DWORD, DWORD, ?*anyopaque, DWORD, DWORD, ?HANDLE) callconv(windows.WINAPI) HANDLE;
extern "kernel32" fn CloseHandle(HANDLE) callconv(windows.WINAPI) BOOL;
extern "kernel32" fn WriteFile(HANDLE, [*]const u8, DWORD, ?*DWORD, ?*anyopaque) callconv(windows.WINAPI) BOOL;

// Global state
var g_nid: NOTIFYICONDATAW = undefined;
var g_hwnd: ?HWND = null;
var g_hInstance: ?HINSTANCE = null;
var g_device_handle: ?HANDLE = null;
var g_device_path: [512]WCHAR = undefined;
var g_device_path_valid: bool = false;

// Protocol header (discovered via Frida trace)
const PACKET_HEADER = [_]u8{ 0xba, 0x70, 0x24, 0x00, 0x00, 0x00, 0x00 };

// On/Off command
const ON_OFF_CMD = [_]u8{ 0x77, 0x58, 0x01, 0x85, 0x01, 0x56 };

// Build the full 64-byte packet
fn buildPacket() [64]u8 {
    var packet: [64]u8 = std.mem.zeroes([64]u8);
    @memcpy(packet[0..PACKET_HEADER.len], &PACKET_HEADER);
    @memcpy(packet[PACKET_HEADER.len .. PACKET_HEADER.len + ON_OFF_CMD.len], &ON_OFF_CMD);
    return packet;
}

// VID/PID pattern to search for in device path (lowercase)
const VID_PID_PATTERN = "vid_0581&pid_011d";

fn toLowerAscii(c: u16) u8 {
    if (c >= 'A' and c <= 'Z') {
        return @truncate(c + ('a' - 'A'));
    }
    if (c < 128) {
        return @truncate(c);
    }
    return 0;
}

fn pathContainsVidPid(path: [*:0]const WCHAR) bool {
    // Convert to lowercase ASCII and search for pattern
    var ascii_buf: [512]u8 = undefined;
    var i: usize = 0;

    while (i < 511) : (i += 1) {
        const c = path[i];
        if (c == 0) break;
        ascii_buf[i] = toLowerAscii(c);
    }
    ascii_buf[i] = 0;

    // Search for pattern
    const pattern = VID_PID_PATTERN;
    if (i < pattern.len) return false;

    var j: usize = 0;
    while (j <= i - pattern.len) : (j += 1) {
        if (std.mem.eql(u8, ascii_buf[j .. j + pattern.len], pattern)) {
            return true;
        }
    }
    return false;
}

fn findNeewerDongle() bool {
    const dev_info = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_HID, null, null, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (dev_info == null) return false;
    defer _ = SetupDiDestroyDeviceInfoList(dev_info);

    var device_index: DWORD = 0;
    while (true) : (device_index += 1) {
        var interface_data: SP_DEVICE_INTERFACE_DATA = undefined;
        interface_data.cbSize = @sizeOf(SP_DEVICE_INTERFACE_DATA);

        if (SetupDiEnumDeviceInterfaces(dev_info, null, &GUID_DEVINTERFACE_HID, device_index, &interface_data) == 0) {
            break; // No more devices
        }

        // Get required size
        var required_size: DWORD = 0;
        _ = SetupDiGetDeviceInterfaceDetailW(dev_info, &interface_data, null, 0, &required_size, null);

        if (required_size == 0 or required_size > 1024) continue;

        // Allocate buffer for detail data
        // SP_DEVICE_INTERFACE_DETAIL_DATA_W: cbSize (DWORD) + DevicePath (WCHAR[])
        // On x64, cbSize must be 8 (4 bytes DWORD + 4 bytes padding before WCHAR array)
        var detail_buffer: [1024]u8 align(8) = undefined;
        const cb_size_ptr: *DWORD = @ptrCast(@alignCast(&detail_buffer));
        cb_size_ptr.* = 8; // Required value for x64

        if (SetupDiGetDeviceInterfaceDetailW(dev_info, &interface_data, @ptrCast(&detail_buffer), required_size, null, null) == 0) {
            continue;
        }

        // Get device path (starts at offset 4)
        const device_path: [*:0]const WCHAR = @ptrCast(@alignCast(&detail_buffer[4]));

        // Check if path contains our VID/PID
        if (pathContainsVidPid(device_path)) {
            // Copy the path for later use
            var k: usize = 0;
            while (k < 511) : (k += 1) {
                g_device_path[k] = device_path[k];
                if (device_path[k] == 0) break;
            }
            g_device_path[k] = 0;
            g_device_path_valid = true;
            return true;
        }
    }

    return false;
}

fn openDevice() ?HANDLE {
    if (!g_device_path_valid) {
        if (!findNeewerDongle()) {
            return null;
        }
    }

    const handle = CreateFileW(
        @ptrCast(&g_device_path),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        null,
        OPEN_EXISTING,
        0,
        null,
    );

    if (handle == INVALID_HANDLE_VALUE) {
        // Device path might be stale, try to rediscover
        g_device_path_valid = false;
        if (!findNeewerDongle()) {
            return null;
        }
        return CreateFileW(
            @ptrCast(&g_device_path),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null,
            OPEN_EXISTING,
            0,
            null,
        );
    }

    return handle;
}

fn toggleLights() bool {
    const handle = openDevice();
    if (handle == null or handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    defer _ = CloseHandle(handle.?);

    const packet = buildPacket();
    var bytes_written: DWORD = 0;

    if (WriteFile(handle.?, &packet, 64, &bytes_written, null) != 0) {
        return bytes_written == 64;
    }

    return false;
}

fn trayAdd(hwnd: HWND) void {
    g_nid = std.mem.zeroes(NOTIFYICONDATAW);
    g_nid.cbSize = @sizeOf(NOTIFYICONDATAW);
    g_nid.hWnd = hwnd;
    g_nid.uID = TRAY_UID;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;

    // Try to load our custom lightbulb icon, fall back to default
    g_nid.hIcon = LoadImageW(g_hInstance, IDI_LIGHTBULB, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    if (g_nid.hIcon == null) {
        g_nid.hIcon = LoadIconW(null, IDI_APPLICATION);
    }

    // Set tooltip
    const tip = std.unicode.utf8ToUtf16LeStringLiteral("Neewer Light Control");
    @memcpy(g_nid.szTip[0..tip.len], tip);

    _ = Shell_NotifyIconW(NIM_ADD, &g_nid);
}

fn trayDelete() void {
    if (g_nid.hWnd != null) {
        _ = Shell_NotifyIconW(NIM_DELETE, &g_nid);
        g_nid.hWnd = null;
    }
}

fn showContextMenu(hwnd: HWND) void {
    const menu = CreatePopupMenu();
    if (menu == null) return;

    const toggle_text = std.unicode.utf8ToUtf16LeStringLiteral("Toggle Lights");
    const exit_text = std.unicode.utf8ToUtf16LeStringLiteral("Exit");

    _ = AppendMenuW(menu, MF_STRING, IDM_TOGGLE, toggle_text);
    _ = AppendMenuW(menu, MF_SEPARATOR, 0, null);
    _ = AppendMenuW(menu, MF_STRING, IDM_EXIT, exit_text);

    var pt: POINT = undefined;
    _ = GetCursorPos(&pt);
    _ = SetForegroundWindow(hwnd);
    _ = TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, null);
    _ = DestroyMenu(menu);
}

fn wndProc(hwnd: HWND, msg: UINT, wParam: WPARAM, lParam: LPARAM) callconv(windows.WINAPI) LRESULT {
    switch (msg) {
        WM_CREATE => {
            g_hwnd = hwnd;
            trayAdd(hwnd);
            return 0;
        },
        WM_TRAYICON => {
            const event: u16 = @truncate(@as(usize, @bitCast(lParam)));
            switch (event) {
                WM_LBUTTONUP => {
                    // Left click: toggle lights
                    if (!toggleLights()) {
                        const msg_text = std.unicode.utf8ToUtf16LeStringLiteral("Dongle not connected!");
                        const msg_title = std.unicode.utf8ToUtf16LeStringLiteral("Neewer Control");
                        _ = MessageBoxW(hwnd, msg_text, msg_title, 0);
                    }
                    return 0;
                },
                WM_RBUTTONUP => {
                    // Right click: show menu
                    showContextMenu(hwnd);
                    return 0;
                },
                else => {},
            }
            return 0;
        },
        WM_COMMAND => {
            const cmd = @as(u16, @truncate(wParam));
            switch (cmd) {
                IDM_TOGGLE => {
                    if (!toggleLights()) {
                        const msg_text = std.unicode.utf8ToUtf16LeStringLiteral("Dongle not connected!");
                        const msg_title = std.unicode.utf8ToUtf16LeStringLiteral("Neewer Control");
                        _ = MessageBoxW(hwnd, msg_text, msg_title, 0);
                    }
                    return 0;
                },
                IDM_EXIT => {
                    _ = DestroyWindow(hwnd);
                    return 0;
                },
                else => {},
            }
            return 0;
        },
        WM_DESTROY => {
            trayDelete();
            PostQuitMessage(0);
            return 0;
        },
        else => return DefWindowProcW(hwnd, msg, wParam, lParam),
    }
}

pub fn main() void {
    const hModule = windows.kernel32.GetModuleHandleW(null);
    const hInstance: ?HINSTANCE = @ptrCast(hModule);
    wWinMain(hInstance);
}

fn wWinMain(hInstance: ?HINSTANCE) void {
    g_hInstance = hInstance;

    const class_name = std.unicode.utf8ToUtf16LeStringLiteral("NeewerTrayClass");

    var wc = WNDCLASSEXW{
        .lpfnWndProc = wndProc,
        .hInstance = hInstance,
        .lpszClassName = class_name,
        .hIcon = LoadIconW(null, IDI_APPLICATION),
    };

    if (RegisterClassExW(&wc) == 0) {
        return;
    }

    const window_name = std.unicode.utf8ToUtf16LeStringLiteral("Neewer Tray Controller");
    const hwnd = CreateWindowExW(0, class_name, window_name, 0, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, null, null, hInstance, null);

    if (hwnd == null) {
        return;
    }

    _ = ShowWindow(hwnd, SW_HIDE);

    var msg: MSG = undefined;
    while (GetMessageW(&msg, null, 0, 0) != 0) {
        _ = TranslateMessage(&msg);
        _ = DispatchMessageW(&msg);
    }
}

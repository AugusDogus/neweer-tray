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

// Windows API types and functions
const HICON = *opaque {};
const HMENU = *opaque {};
const POINT = extern struct { x: i32, y: i32 };

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
const LR_SHARED: UINT = 0x00008000;
const IDI_LIGHTBULB: usize = 1; // Our custom icon resource ID
const TPM_RIGHTBUTTON: UINT = 0x0002;
const TPM_BOTTOMALIGN: UINT = 0x0020;
const MF_STRING: UINT = 0x00000000;
const MF_SEPARATOR: UINT = 0x00000800;

const CW_USEDEFAULT: i32 = @bitCast(@as(u32, 0x80000000));
const SW_HIDE: i32 = 0;

const TRAY_UID: UINT = 1001;
const IDM_TOGGLE: UINT = 2001;
const IDM_EXIT: UINT = 2002;

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

// Neewer DLL function types
const GetUsbStateFn = *const fn () callconv(windows.WINAPI) c_int;
const SendRfDataFn = *const fn ([*]const u8, c_int) callconv(windows.WINAPI) c_int;

// Global state
var g_nid: NOTIFYICONDATAW = undefined;
var g_hwnd: ?HWND = null;
var g_hInstance: ?HINSTANCE = null;
var g_neewer_dll: ?windows.HMODULE = null;
var g_get_usb_state: ?GetUsbStateFn = null;
var g_send_rf_data: ?SendRfDataFn = null;

// On/Off command packet (32 bytes)
const ON_OFF_PACKET = [_]u8{
    0x77, 0x58, 0x01, 0x85, 0x01, 0x56, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

fn loadNeewerDll() bool {
    const dll_path = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Neewer Control Center\\Neewer\\Set_Dongle_RF_API_x64.dll");

    g_neewer_dll = windows.kernel32.LoadLibraryW(dll_path);
    if (g_neewer_dll == null) {
        return false;
    }

    const dll = g_neewer_dll.?;

    if (windows.kernel32.GetProcAddress(dll, "Get_USB_State")) |proc| {
        g_get_usb_state = @ptrCast(proc);
    } else {
        return false;
    }

    if (windows.kernel32.GetProcAddress(dll, "Send_RF_DATA")) |proc| {
        g_send_rf_data = @ptrCast(proc);
    } else {
        return false;
    }

    return true;
}

fn isDongleConnected() bool {
    if (g_get_usb_state) |func| {
        return func() == 1;
    }
    return false;
}

fn toggleLights() bool {
    if (g_send_rf_data) |func| {
        const result = func(&ON_OFF_PACKET, ON_OFF_PACKET.len);
        return result == 0;
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
                    if (isDongleConnected()) {
                        _ = toggleLights();
                    } else {
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
                    if (isDongleConnected()) {
                        _ = toggleLights();
                    } else {
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
            if (g_neewer_dll) |dll| {
                _ = windows.kernel32.FreeLibrary(dll);
                g_neewer_dll = null;
            }
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

    // Load Neewer DLL
    if (!loadNeewerDll()) {
        const msg_text = std.unicode.utf8ToUtf16LeStringLiteral("Failed to load Neewer DLL!\nMake sure Neewer Control Center is installed.");
        const msg_title = std.unicode.utf8ToUtf16LeStringLiteral("Error");
        _ = MessageBoxW(null, msg_text, msg_title, 0);
        return;
    }

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
    const hwnd = CreateWindowExW(0, class_name, window_name, 0, // WS_OVERLAPPED
        CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, null, null, hInstance, null);

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

// Use standard main - libc provides the entry point

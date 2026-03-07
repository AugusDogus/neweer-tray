const std = @import("std");
const neewer = @import("neewer.zig");

const c = @cImport({
    @cInclude("gio/gio.h");
    @cInclude("glib-object.h");
    @cInclude("hidapi/hidapi.h");
});

const object_path = "/StatusNotifierItem";
const menu_path = "/StatusNotifierItem/Menu";
const title = "Neewer Light Control";
const tooltip_text = "Click to toggle lights";
const icon_name = "display-brightness-symbolic";

const sni_xml =
    \\<node>
    \\  <interface name="org.kde.StatusNotifierItem">
    \\    <method name="Activate">
    \\      <arg type="i" name="x" direction="in"/>
    \\      <arg type="i" name="y" direction="in"/>
    \\    </method>
    \\    <method name="SecondaryActivate">
    \\      <arg type="i" name="x" direction="in"/>
    \\      <arg type="i" name="y" direction="in"/>
    \\    </method>
    \\    <method name="ContextMenu">
    \\      <arg type="i" name="x" direction="in"/>
    \\      <arg type="i" name="y" direction="in"/>
    \\    </method>
    \\    <method name="Scroll">
    \\      <arg type="i" name="delta" direction="in"/>
    \\      <arg type="s" name="orientation" direction="in"/>
    \\    </method>
    \\    <property type="s" name="Category" access="read"/>
    \\    <property type="s" name="Id" access="read"/>
    \\    <property type="s" name="Title" access="read"/>
    \\    <property type="s" name="Status" access="read"/>
    \\    <property type="u" name="WindowId" access="read"/>
    \\    <property type="s" name="IconName" access="read"/>
    \\    <property type="(sa(iiay)ss)" name="ToolTip" access="read"/>
    \\    <property type="b" name="ItemIsMenu" access="read"/>
    \\    <property type="o" name="Menu" access="read"/>
    \\    <signal name="NewIcon"/>
    \\    <signal name="NewToolTip"/>
    \\    <signal name="NewStatus">
    \\      <arg type="s" name="status"/>
    \\    </signal>
    \\  </interface>
    \\</node>
;

const AppState = struct {
    connection: ?*c.GDBusConnection = null,
    loop: ?*c.GMainLoop = null,
    introspection: ?*c.GDBusNodeInfo = null,
    object_registration_id: c.guint = 0,
    service_name_buf: [64:0]u8 = undefined,
};

var app_state: AppState = .{};

fn cStrEq(value: [*c]const u8, expected: []const u8) bool {
    return std.mem.eql(u8, std.mem.span(value), expected);
}

fn printGError(prefix: []const u8, err: ?*c.GError) void {
    if (err) |e| {
        const message = if (e.message != null) std.mem.span(e.message) else "unknown error";
        std.log.err("{s}: {s}", .{ prefix, message });
        c.g_error_free(e);
    } else {
        std.log.err("{s}", .{prefix});
    }
}

fn buildToolTipVariant() ?*c.GVariant {
    var children = [_]?*c.GVariant{
        c.g_variant_new_string(""),
        c.g_variant_new_array(c.g_variant_type_checked_("(iiay)"), null, 0),
        c.g_variant_new_string(title),
        c.g_variant_new_string(tooltip_text),
    };
    return c.g_variant_new_tuple(@ptrCast(&children), children.len);
}

fn tryTogglePath(path: [*:0]const u8) bool {
    const device = c.hid_open_path(path);
    if (device == null) return false;
    defer _ = c.hid_close(device);

    const write_64 = neewer.buildHidWritePacket();
    if (c.hid_write(device, @ptrCast(&write_64), write_64.len) >= 0) return true;

    const output_64 = neewer.buildHidWritePacket();
    if (c.hid_send_output_report(device, @ptrCast(&output_64), output_64.len) >= 0) return true;

    const write_32 = neewer.buildLegacyHidWritePacket();
    if (c.hid_write(device, @ptrCast(&write_32), write_32.len) >= 0) return true;

    return false;
}

fn toggleLights() bool {
    const device_list = c.hid_enumerate(neewer.vid, neewer.pid);
    if (device_list == null) return false;
    defer c.hid_free_enumeration(device_list);

    var current = device_list;
    while (current != null) : (current = current.*.next) {
        if (current.*.path != null and tryTogglePath(current.*.path)) {
            return true;
        }
    }

    return false;
}

fn returnUnknownMethod(invocation: ?*c.GDBusMethodInvocation) void {
    c.g_dbus_method_invocation_return_dbus_error(
        invocation,
        "org.freedesktop.DBus.Error.UnknownMethod",
        "Unsupported tray action",
    );
}

fn handleMethodCall(
    connection: ?*c.GDBusConnection,
    sender: [*c]const u8,
    invoked_object_path: [*c]const u8,
    interface_name: [*c]const u8,
    method_name: [*c]const u8,
    parameters: ?*c.GVariant,
    invocation: ?*c.GDBusMethodInvocation,
    user_data: ?*anyopaque,
) callconv(.c) void {
    _ = connection;
    _ = sender;
    _ = invoked_object_path;
    _ = interface_name;
    _ = parameters;
    _ = user_data;

    if (cStrEq(method_name, "Activate") or cStrEq(method_name, "SecondaryActivate")) {
        if (!toggleLights()) {
            c.g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.neewer.Tray.Error.DongleUnavailable",
                "Neewer dongle not connected",
            );
            return;
        }

        c.g_dbus_method_invocation_return_value(invocation, null);
        return;
    }

    if (cStrEq(method_name, "ContextMenu") or cStrEq(method_name, "Scroll")) {
        c.g_dbus_method_invocation_return_value(invocation, null);
        return;
    }

    returnUnknownMethod(invocation);
}

fn handleGetProperty(
    connection: ?*c.GDBusConnection,
    sender: [*c]const u8,
    invoked_object_path: [*c]const u8,
    interface_name: [*c]const u8,
    property_name: [*c]const u8,
    err: ?*?*c.GError,
    user_data: ?*anyopaque,
) callconv(.c) ?*c.GVariant {
    _ = connection;
    _ = sender;
    _ = invoked_object_path;
    _ = interface_name;
    _ = err;
    _ = user_data;

    if (cStrEq(property_name, "Category")) return c.g_variant_new_string("Hardware");
    if (cStrEq(property_name, "Id")) return c.g_variant_new_string("neewer-tray");
    if (cStrEq(property_name, "Title")) return c.g_variant_new_string(title);
    if (cStrEq(property_name, "Status")) return c.g_variant_new_string("Active");
    if (cStrEq(property_name, "WindowId")) return c.g_variant_new_uint32(0);
    if (cStrEq(property_name, "IconName")) return c.g_variant_new_string(icon_name);
    if (cStrEq(property_name, "ToolTip")) return buildToolTipVariant();
    if (cStrEq(property_name, "ItemIsMenu")) return c.g_variant_new_boolean(0);
    if (cStrEq(property_name, "Menu")) return c.g_variant_new_object_path(menu_path);

    return null;
}

const interface_vtable = c.GDBusInterfaceVTable{
    .method_call = handleMethodCall,
    .get_property = handleGetProperty,
    .set_property = null,
};

fn requestBusName(connection: *c.GDBusConnection, service_name: [*:0]const u8) !void {
    var err: ?*c.GError = null;
    const reply = c.g_dbus_connection_call_sync(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RequestName",
        c.g_variant_new("(su)", service_name, @as(c.guint, 0)),
        c.g_variant_type_checked_("(u)"),
        c.G_DBUS_CALL_FLAGS_NONE,
        -1,
        null,
        &err,
    );
    if (err != null or reply == null) {
        printGError("failed to acquire session bus name", err);
        return error.RequestNameFailed;
    }
    c.g_variant_unref(reply);
}

fn registerWatcher(connection: *c.GDBusConnection, service_name: [*:0]const u8) !void {
    const watcher_bus_names = [_][]const u8{
        "org.kde.StatusNotifierWatcher",
        "org.freedesktop.StatusNotifierWatcher",
    };
    const watcher_ifaces = [_][]const u8{
        "org.kde.StatusNotifierWatcher",
        "org.freedesktop.StatusNotifierWatcher",
    };

    inline for (watcher_bus_names, watcher_ifaces) |bus_name, iface_name| {
        var err: ?*c.GError = null;
        const reply = c.g_dbus_connection_call_sync(
            connection,
            bus_name.ptr,
            "/StatusNotifierWatcher",
            iface_name.ptr,
            "RegisterStatusNotifierItem",
            c.g_variant_new("(s)", service_name),
            null,
            c.G_DBUS_CALL_FLAGS_NONE,
            -1,
            null,
            &err,
        );

        if (err == null and reply != null) {
            c.g_variant_unref(reply);
            return;
        }

        if (reply != null) c.g_variant_unref(reply);
        if (err != null) c.g_error_free(err);
    }

    return error.WatcherUnavailable;
}

pub fn run() !void {
    if (c.hid_init() != 0) return error.HidInitFailed;
    defer _ = c.hid_exit();

    const service_name = try std.fmt.bufPrintZ(
        &app_state.service_name_buf,
        "org.kde.StatusNotifierItem-{d}-1",
        .{std.os.linux.getpid()},
    );

    var err: ?*c.GError = null;
    const connection = c.g_bus_get_sync(c.G_BUS_TYPE_SESSION, null, &err);
    if (err != null or connection == null) {
        printGError("failed to connect to session bus", err);
        return error.SessionBusUnavailable;
    }
    const bus = connection.?;
    app_state.connection = bus;
    defer c.g_object_unref(bus);

    try requestBusName(bus, service_name.ptr);

    const node_info = c.g_dbus_node_info_new_for_xml(sni_xml, &err);
    if (err != null or node_info == null) {
        printGError("failed to parse tray D-Bus interface", err);
        return error.IntrospectionFailed;
    }
    app_state.introspection = node_info;
    defer c.g_dbus_node_info_unref(node_info);

    const iface_info = c.g_dbus_node_info_lookup_interface(node_info, "org.kde.StatusNotifierItem");
    if (iface_info == null) return error.InterfaceLookupFailed;

    const registration_id = c.g_dbus_connection_register_object(
        bus,
        object_path,
        iface_info,
        &interface_vtable,
        null,
        null,
        &err,
    );
    if (err != null or registration_id == 0) {
        printGError("failed to register tray object", err);
        return error.ObjectRegistrationFailed;
    }
    app_state.object_registration_id = registration_id;

    try registerWatcher(bus, service_name.ptr);

    const loop = c.g_main_loop_new(null, 0);
    if (loop == null) return error.MainLoopFailed;
    app_state.loop = loop;
    defer c.g_main_loop_unref(loop);

    std.log.info("Neewer tray running on Linux top bar", .{});
    c.g_main_loop_run(loop);
}

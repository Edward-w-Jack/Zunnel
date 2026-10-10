//! Windows service support for the agent (-Dagent-service builds). Exposes
//! three commands:
//!
//!   zunnel-agent install-service [-service-name <name>]
//!   zunnel-agent uninstall-service [-service-name <name>]
//!   (invoked by SCM, no arguments) -> runs under SCM, agent runs in a worker thread
//!
//! The service is created with SERVICE_AUTO_START as LocalSystem. Its binary
//! path is the current exe path, so the baked-in config (`-Dagent-connect`
//! and friends) is what the service actually uses -- there is no way to pass
//! arguments through SCM.
const std = @import("std");
const builtin = @import("builtin");
const agent = @import("agent.zig");

const win = std.os.windows;
const utf16Z = std.unicode.utf8ToUtf16LeStringLiteral;
const log = std.log.scoped(.service);

pub const default_service_name = "ZunnelAgent";
pub const default_service_display = "Zunnel Agent";

// ------------------------------------------------------- Windows API binding

const SC_HANDLE = win.HANDLE;
const SERVICE_STATUS_HANDLE = win.HANDLE;

const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
const SERVICE_AUTO_START: u32 = 2;
const SERVICE_ERROR_NORMAL: u32 = 1;
const SERVICE_START_PENDING: u32 = 2;
const SERVICE_STOP_PENDING: u32 = 3;
const SERVICE_RUNNING: u32 = 4;
const SERVICE_STOPPED: u32 = 1;
const SERVICE_ACCEPT_STOP: u32 = 1;
const SERVICE_ACCEPT_SHUTDOWN: u32 = 4;
const SERVICE_CONTROL_STOP: u32 = 1;
const SERVICE_CONTROL_SHUTDOWN: u32 = 5;
const SERVICE_CONTROL_INTERROGATE: u32 = 4;
const SC_MANAGER_ALL_ACCESS: u32 = 0xf003f;
const SERVICE_ALL_ACCESS: u32 = 0xf01ff;
const ERROR_SERVICE_EXISTS: u32 = 1073;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;

const SERVICE_STATUS = extern struct {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
};

const SERVICE_TABLE_ENTRYW = extern struct {
    service_name: ?[*:0]const u16,
    service_proc: ?ServiceMainFn,
};

const ServiceMainFn = *const fn (argc: u32, argv: ?[*][*:0]const u16) callconv(.winapi) void;
const HandlerExFn = *const fn (control: u32, event_type: u32, event_data: ?*anyopaque, ctx: ?*anyopaque) callconv(.winapi) u32;

extern "advapi32" fn StartServiceCtrlDispatcherW(table: [*]const SERVICE_TABLE_ENTRYW) callconv(.winapi) win.BOOL;
extern "advapi32" fn RegisterServiceCtrlHandlerExW(name: [*:0]const u16, handler: HandlerExFn, ctx: ?*anyopaque) callconv(.winapi) ?SERVICE_STATUS_HANDLE;
extern "advapi32" fn SetServiceStatus(h: SERVICE_STATUS_HANDLE, status: *const SERVICE_STATUS) callconv(.winapi) win.BOOL;
extern "advapi32" fn OpenSCManagerW(machine: ?[*:0]const u16, database: ?[*:0]const u16, access: u32) callconv(.winapi) ?SC_HANDLE;
extern "advapi32" fn CloseServiceHandle(h: SC_HANDLE) callconv(.winapi) win.BOOL;
extern "advapi32" fn CreateServiceW(
    scm: SC_HANDLE,
    name: [*:0]const u16,
    display: ?[*:0]const u16,
    access: u32,
    service_type: u32,
    start: u32,
    error_control: u32,
    binary_path: [*:0]const u16,
    group: ?[*:0]const u16,
    tag_id: ?*u32,
    deps: ?[*:0]const u16,
    start_name: ?[*:0]const u16,
    pw: ?[*:0]const u16,
) callconv(.winapi) ?SC_HANDLE;
extern "advapi32" fn OpenServiceW(scm: SC_HANDLE, name: [*:0]const u16, access: u32) callconv(.winapi) ?SC_HANDLE;
extern "advapi32" fn DeleteService(h: SC_HANDLE) callconv(.winapi) win.BOOL;
extern "kernel32" fn GetModuleFileNameW(mod: ?win.HMODULE, buf: [*]u16, size: u32) callconv(.winapi) u32;

// --------------------------------------------------------- service runtime

const ServiceState = struct {
    status_handle: SERVICE_STATUS_HANDLE,
    stop: std.atomic.Value(bool),
};

var state: ServiceState = undefined;
var state_initialized: bool = false;

fn setStatus(h: SERVICE_STATUS_HANDLE, state_code: u32, wait_hint_ms: u32, check_point: u32) void {
    const accepts: u32 = if (state_code == SERVICE_RUNNING) SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN else 0;
    const status: SERVICE_STATUS = .{
        .service_type = SERVICE_WIN32_OWN_PROCESS,
        .current_state = state_code,
        .controls_accepted = accepts,
        .exit_code = 0,
        .service_specific_exit_code = 0,
        .check_point = check_point,
        .wait_hint = wait_hint_ms,
    };
    _ = SetServiceStatus(h, &status);
}

fn controlHandler(control: u32, _: u32, _: ?*anyopaque, _: ?*anyopaque) callconv(.winapi) u32 {
    switch (control) {
        SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN => {
            setStatus(state.status_handle, SERVICE_STOP_PENDING, 30_000, 1);
            state.stop.store(true, .release);
            return 0; // NO_ERROR
        },
        SERVICE_CONTROL_INTERROGATE => return 0,
        else => return 0,
    }
}

/// SCM invokes this on a worker thread after StartServiceCtrlDispatcherW.
/// SCM waits for us to report RUNNING; keep that window short.
fn serviceMain(_: u32, _: ?[*][*:0]const u16) callconv(.winapi) void {
    const h = RegisterServiceCtrlHandlerExW(utf16Z(default_service_name), controlHandler, null) orelse return;
    state = .{ .status_handle = h, .stop = .init(false) };
    state_initialized = true;

    setStatus(h, SERVICE_START_PENDING, 30_000, 1);

    // No console under SCM: silence log output regardless of the windowed flag.
    agent.quiet = true;

    // Build the agent config from baked options alone -- SCM gives us no argv.
    // If it isn't baked, exit with a status that'll show up in Event Viewer.
    const gpa = std.heap.smp_allocator;
    const main_mod = @import("main.zig");
    const layers = [_]@import("config.zig").Layer{ main_mod.bakedLayer() };
    const cfg = @import("config.zig").resolve(&layers, std.time.milliTimestamp()) catch {
        setStatus(h, SERVICE_STOPPED, 0, 0);
        return;
    };

    setStatus(h, SERVICE_RUNNING, 0, 0);
    _ = agent.run(gpa, cfg, &state.stop);
    setStatus(h, SERVICE_STOPPED, 0, 0);
}

/// Tries to connect to SCM as a service. Returns true if we were started by
/// SCM (the dispatcher runs the agent and this function returns on service
/// stop); false if we were started from a user shell (fall through to the
/// normal main).
pub fn tryDispatch() bool {
    var table = [_]SERVICE_TABLE_ENTRYW{
        .{ .service_name = utf16Z(default_service_name), .service_proc = serviceMain },
        .{ .service_name = null, .service_proc = null },
    };
    if (StartServiceCtrlDispatcherW(&table) != 0) return true;
    const err = win.kernel32.GetLastError();
    if (@intFromEnum(err) != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
        log.err("StartServiceCtrlDispatcher failed: {d}", .{@intFromEnum(err)});
    }
    return false;
}

// ------------------------------------------------------- install / uninstall

fn exePath(gpa: std.mem.Allocator) ![:0]u16 {
    var buf: [win.MAX_PATH]u16 = undefined;
    const n = GetModuleFileNameW(null, &buf, buf.len);
    if (n == 0 or n >= buf.len) return error.PathTooLong;
    return gpa.dupeZ(u16, buf[0..n]);
}

pub fn install(gpa: std.mem.Allocator) !void {
    const scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS) orelse {
        std.debug.print("OpenSCManager failed (error {d}); re-run from an elevated prompt\n", .{@intFromEnum(win.kernel32.GetLastError())});
        return error.AccessDenied;
    };
    defer _ = CloseServiceHandle(scm);
    const path = try exePath(gpa);
    defer gpa.free(path);

    const h = CreateServiceW(
        scm,
        utf16Z(default_service_name),
        utf16Z(default_service_display),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        path.ptr,
        null,
        null,
        null,
        null, // LocalSystem
        null,
    ) orelse {
        const err = @intFromEnum(win.kernel32.GetLastError());
        if (err == ERROR_SERVICE_EXISTS) {
            std.debug.print("service '{s}' already installed; uninstall-service first\n", .{default_service_name});
            return error.AlreadyExists;
        }
        std.debug.print("CreateService failed (error {d})\n", .{err});
        return error.CreateFailed;
    };
    _ = CloseServiceHandle(h);
    std.debug.print("installed '{s}' (auto-start, LocalSystem); start with: sc start {s}\n", .{ default_service_display, default_service_name });
}

pub fn uninstall() !void {
    const scm = OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS) orelse {
        std.debug.print("OpenSCManager failed (error {d}); re-run from an elevated prompt\n", .{@intFromEnum(win.kernel32.GetLastError())});
        return error.AccessDenied;
    };
    defer _ = CloseServiceHandle(scm);
    const svc = OpenServiceW(scm, utf16Z(default_service_name), SERVICE_ALL_ACCESS) orelse {
        std.debug.print("service '{s}' not installed\n", .{default_service_name});
        return error.NotInstalled;
    };
    defer _ = CloseServiceHandle(svc);
    if (DeleteService(svc) == 0) {
        std.debug.print("DeleteService failed (error {d})\n", .{@intFromEnum(win.kernel32.GetLastError())});
        return error.DeleteFailed;
    }
    std.debug.print("uninstalled '{s}'\n", .{default_service_display});
}

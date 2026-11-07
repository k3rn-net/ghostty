//! Windows checks for the Kitty graphics protocol's file, temporary
//! file and shared memory mediums.
//!
//! On POSIX the file transmission blocklist is a few prefixes
//! (`/proc`, `/sys`, `/dev`) applied to the canonical path of the
//! opened file. Windows needs more care because some paths are
//! dangerous to even open: a UNC path makes this process resolve and
//! authenticate to the named SMB server, and the Win32 device and NT
//! object namespaces reach raw volumes and named pipes, where the
//! open or the read can block.
//!
//! Everything here is pure string logic, so it is tested on every host.

const std = @import("std");

pub const Error = error{
    /// A UNC path such as `\\server\share`, in any mix of `\` and `/`.
    /// Opening it resolves the host name and authenticates to the
    /// server over SMB.
    UncPath,

    /// A Win32 device path (`\\.\`, `\\?\`) or an NT object path
    /// (`\??\`). These reach raw volumes, named pipes, and through
    /// `GLOBALROOT` any kernel object.
    DevicePath,

    /// A component names a reserved DOS device such as CON or COM1.
    /// Windows resolves these to the device from inside any directory.
    ReservedDeviceName,

    /// The canonical path of an opened file is not `X:\...`, so the
    /// file is not on a local volume with a drive letter. The canonical
    /// path of a file on an SMB share is a UNC path, for example.
    NotDriveAbsolute,
};

/// Check a path supplied by a client before it is opened. This never
/// touches the filesystem. A plain local path of any shape passes:
/// drive-absolute, drive-relative, rooted, or relative. Whether it
/// resolves to a local regular file is decided after the open with
/// `checkCanonicalPath`.
pub fn checkPath(path: []const u8) Error!void {
    if (path.len >= 2 and isSep(path[0]) and isSep(path[1])) {
        // `\\?\` and `\\.\` are the Win32 device namespace. Anything
        // else after two separators is a server name.
        if (path.len >= 4 and
            (path[2] == '?' or path[2] == '.') and
            isSep(path[3])) return error.DevicePath;
        return error.UncPath;
    }

    if (path.len >= 4 and
        isSep(path[0]) and
        path[1] == '?' and
        path[2] == '?' and
        isSep(path[3])) return error.DevicePath;

    var it = std.mem.splitAny(u8, path, "\\/");
    while (it.next()) |component| {
        if (isReservedDeviceName(component)) return error.ReservedDeviceName;
    }
}

/// Check the canonical path of an opened file, as produced by
/// `GetFinalPathNameByHandle`. The file must be on a local volume with
/// a drive letter, and the checks of `checkPath` apply as well.
pub fn checkCanonicalPath(path: []const u8) Error!void {
    if (!isDriveAbsolute(path)) return error.NotDriveAbsolute;
    try checkPath(path);
}

/// Returns true if `path` is a drive-absolute path (`C:\...`), the
/// only shape the canonical path of a file on a local volume with a
/// drive letter takes.
pub fn isDriveAbsolute(path: []const u8) bool {
    return path.len >= 3 and
        std.ascii.isAlphabetic(path[0]) and
        path[1] == ':' and
        path[2] == '\\';
}

/// The longest shared memory name a client may send, in bytes. Windows
/// takes object names of up to MAX_PATH characters.
pub const shared_memory_name_max = 260;

pub const SharedMemoryNameError = error{
    /// Empty, longer than `shared_memory_name_max`, or with a NUL.
    InvalidSharedMemoryName,

    /// A name in another namespace than the session's own: `Global\`,
    /// `Session\N\`, a private namespace, or any other path. On Windows
    /// a client names the mapping it made, and it made it in its session.
    SharedMemoryNameOutsideSession,
};

/// Check the name of a shared memory object a client asks the terminal
/// to read: a plain name, or one in `Local\`, the session's own
/// namespace. What the name may reach is still only what this user may
/// open; this keeps a client from steering the read anywhere else.
pub fn checkSharedMemoryName(name: []const u8) SharedMemoryNameError!void {
    if (name.len == 0 or name.len > shared_memory_name_max) return error.InvalidSharedMemoryName;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return error.InvalidSharedMemoryName;
    const local = "Local\\";
    const plain = if (name.len > local.len and std.ascii.startsWithIgnoreCase(name, local))
        name[local.len..]
    else
        name;
    if (std.mem.indexOfAny(u8, plain, "\\/") != null) return error.SharedMemoryNameOutsideSession;
}

/// Returns true if `c` is a Windows path separator.
fn isSep(c: u8) bool {
    return std.fs.path.PathType.windows.isSep(u8, c);
}

/// Returns true if a path component names a reserved DOS device: CON,
/// PRN, AUX, NUL, COM0 to COM9, LPT0 to LPT9, and the superscript digit
/// variants.
fn isReservedDeviceName(component: []const u8) bool {
    // The name ends at the extension or stream separator.
    const end = std.mem.findAny(u8, component, ".:") orelse component.len;
    const stem = std.mem.trimEnd(u8, component[0..end], " ");
    if (stem.len < 3) return false;

    const base = stem[0..3];
    const rest = stem[3..];
    if (rest.len == 0) {
        return std.ascii.eqlIgnoreCase(base, "CON") or
            std.ascii.eqlIgnoreCase(base, "PRN") or
            std.ascii.eqlIgnoreCase(base, "AUX") or
            std.ascii.eqlIgnoreCase(base, "NUL");
    }

    if (!std.ascii.eqlIgnoreCase(base, "COM") and
        !std.ascii.eqlIgnoreCase(base, "LPT")) return false;
    return switch (rest.len) {
        1 => std.ascii.isDigit(rest[0]),
        // U+00B9, U+00B2, U+00B3 (¹ ² ³) encoded as WTF-8.
        2 => rest[0] == 0xC2 and
            (rest[1] == 0xB9 or rest[1] == 0xB2 or rest[1] == 0xB3),
        else => false,
    };
}

test "checkSharedMemoryName takes a plain name or one of the session's own" {
    try checkSharedMemoryName("kitty-123-4");
    try checkSharedMemoryName("Local\\kitty-123-4");
    try checkSharedMemoryName("local\\kitty");
    const longest: [shared_memory_name_max]u8 = @splat('a');
    try checkSharedMemoryName(&longest);
}

test "checkSharedMemoryName refuses other namespaces and malformed names" {
    const testing = std.testing;
    try testing.expectError(error.InvalidSharedMemoryName, checkSharedMemoryName(""));
    try testing.expectError(error.InvalidSharedMemoryName, checkSharedMemoryName("kitty\x00image"));
    const too_long: [shared_memory_name_max + 1]u8 = @splat('a');
    try testing.expectError(error.InvalidSharedMemoryName, checkSharedMemoryName(&too_long));
    try testing.expectError(error.SharedMemoryNameOutsideSession, checkSharedMemoryName("Global\\kitty"));
    try testing.expectError(error.SharedMemoryNameOutsideSession, checkSharedMemoryName("Session\\2\\kitty"));
    try testing.expectError(error.SharedMemoryNameOutsideSession, checkSharedMemoryName("Local\\a\\b"));
    try testing.expectError(error.SharedMemoryNameOutsideSession, checkSharedMemoryName("Local\\"));
    try testing.expectError(error.SharedMemoryNameOutsideSession, checkSharedMemoryName("ns/kitty"));
}

test "checkPath rejects UNC paths" {
    const testing = std.testing;

    const unc = [_][]const u8{
        "\\\\server\\share\\tty-graphics-protocol-image.data",
        "//server/share/tty-graphics-protocol-image.data",
        "\\/server/share/image.data",
        "/\\server\\share\\image.data",
        "\\\\.x\\share\\image.data",
        "\\\\",
    };
    for (unc) |path| {
        try testing.expectError(error.UncPath, checkPath(path));
    }
}

test "checkPath rejects device and NT namespaces" {
    const testing = std.testing;

    const device = [_][]const u8{
        "\\\\?\\UNC\\server\\share\\image.data",
        "\\\\?\\C:\\Windows\\Temp\\image.data",
        "//?/C:/Windows/Temp/image.data",
        "\\\\.\\C:\\Windows\\Temp\\image.data",
        "\\\\.\\pipe\\image",
        "\\\\.\\PhysicalDrive0",
        "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\image.data",
        "//?/GLOBALROOT/Device/HarddiskVolume1/image.data",
        "\\??\\C:\\Windows\\Temp\\image.data",
        "\\??\\Device\\HarddiskVolume1\\image.data",
        "\\??\\UNC\\server\\share\\image.data",
        "/??/C:/image.data",
    };
    for (device) |path| {
        try testing.expectError(error.DevicePath, checkPath(path));
    }
}

test "checkPath accepts plain local paths" {
    const accepted = [_][]const u8{
        "C:\\Windows\\Temp\\tty-graphics-protocol-image.data",
        "C:/Windows/Temp/tty-graphics-protocol-image.data",
        "c:\\image.data",
        "C:image.data",
        "\\Windows\\Temp\\image.data",
        "/Windows/Temp/image.data",
        "image.data",
        ".zig-cache\\tmp\\image.data",
        "C:\\Device\\HarddiskVolume1\\image.data",
        "C:\\GLOBALROOT\\image.data",
        "C:\\dir\\console.png",
        "\\?\\image.data",
        "",
    };
    for (accepted) |path| {
        try checkPath(path);
    }
}

test "checkPath rejects reserved device names in any component" {
    const testing = std.testing;

    const reserved = [_][]const u8{
        "CON",
        "con",
        "CON.png",
        "CON.tar.gz",
        "CON.",
        "CON  ",
        "CON .png",
        "NUL:stream",
        "PRN",
        "AUX",
        "nul",
        "COM1",
        "COM0",
        "COM9.rgba",
        "com5",
        "LPT1",
        "LPT9",
        "lpt0.png",
        "COM\xC2\xB9",
        "LPT\xC2\xB3.png",
        "C:\\Windows\\Temp\\NUL.rgba",
        "C:\\CON\\image.data",
        "dir/aux/image.data",
        "C:/Windows/Temp/com1",
        "..\\PRN",
    };
    for (reserved) |path| {
        try testing.expectError(error.ReservedDeviceName, checkPath(path));
    }

    const plain = [_][]const u8{
        "CONSOLE",
        "CON1",
        "xCON",
        " CON",
        "COM",
        "COM10",
        "COMA",
        "COM\xC2\xB9\xC2\xB9",
        "COM\xC2\xB0",
        "LPT",
        "LPT.png",
        "conx.png",
        "C:",
        "C:\\",
        "image.data",
        "C:\\Windows\\Temp\\tty-graphics-protocol-image.data",
        "C:\\Windows\\Temp\\console.png",
        "",
    };
    for (plain) |path| {
        try checkPath(path);
    }
}

test "checkCanonicalPath requires a drive-absolute local path" {
    const testing = std.testing;

    try checkCanonicalPath("C:\\Windows\\Temp\\image.data");
    try checkCanonicalPath("c:\\image.data");

    // Shapes GetFinalPathNameByHandle produces for files that are not
    // on a local drive-letter volume.
    try testing.expectError(
        error.NotDriveAbsolute,
        checkCanonicalPath("\\\\server\\share\\image.data"),
    );
    try testing.expectError(
        error.NotDriveAbsolute,
        checkCanonicalPath("\\\\?\\UNC\\server\\share\\image.data"),
    );
    try testing.expectError(
        error.NotDriveAbsolute,
        checkCanonicalPath("\\\\?\\Volume{383da0b0-717f-41b6-8c36-00500992b58d}\\image.data"),
    );

    // The raw path checks still apply to the canonical form.
    try testing.expectError(
        error.ReservedDeviceName,
        checkCanonicalPath("C:\\Windows\\Temp\\CON"),
    );
}

test isDriveAbsolute {
    const testing = std.testing;

    try testing.expect(isDriveAbsolute("C:\\Windows\\Temp\\image.data"));
    try testing.expect(isDriveAbsolute("c:\\image.data"));
    try testing.expect(isDriveAbsolute("Z:\\"));

    try testing.expect(!isDriveAbsolute("\\\\server\\share\\image.data"));
    try testing.expect(!isDriveAbsolute("UNC\\server\\share\\image.data"));
    try testing.expect(!isDriveAbsolute("C:/Windows/image.data"));
    try testing.expect(!isDriveAbsolute("C:image.data"));
    try testing.expect(!isDriveAbsolute("\\Windows\\image.data"));
    try testing.expect(!isDriveAbsolute("1:\\image.data"));
    try testing.expect(!isDriveAbsolute("C:"));
    try testing.expect(!isDriveAbsolute(""));
}

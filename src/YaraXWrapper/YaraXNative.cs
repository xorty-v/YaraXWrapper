using System;
using System.Runtime.InteropServices;
using System.Text;

namespace YaraXWrapper;

internal enum YRX_RESULT
{
    YRX_SUCCESS,
    YRX_SYNTAX_ERROR,
    YRX_VARIABLE_ERROR,
    YRX_SCAN_ERROR,
    YRX_SCAN_TIMEOUT,
    YRX_INVALID_ARGUMENT,
    YRX_INVALID_UTF8,
    YRX_INVALID_STATE,
    YRX_SERIALIZATION_ERROR,
    YRX_NO_METADATA,
    YRX_NOT_SUPPORTED,
}

[StructLayout(LayoutKind.Sequential)]
internal struct YRX_BUFFER
{
    public IntPtr data;
    public UIntPtr length;
}

[StructLayout(LayoutKind.Sequential)]
internal struct YRX_MATCH
{
    public ulong offset;
    public ulong length;
}

// Manual UTF-8 encoding: [DllImport] CharSet.Ansi marshals through the system ANSI code
// page, which breaks non-ASCII input. The YARA-X C API requires valid UTF-8 on all string
// arguments and will reject ANSI-encoded bytes.
internal sealed class Utf8NativeStr : IDisposable
{
    private IntPtr _ptr;

    internal Utf8NativeStr(string? s)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(s ?? string.Empty);
        _ptr = Marshal.AllocHGlobal(bytes.Length + 1);
        Marshal.Copy(bytes, 0, _ptr, bytes.Length);
        Marshal.WriteByte(_ptr, bytes.Length, 0);
    }

    public static implicit operator IntPtr(Utf8NativeStr s) => s._ptr;

    public void Dispose()
    {
        if (_ptr != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(_ptr);
            _ptr = IntPtr.Zero;
        }
    }
}

internal static class YaraXNative
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_RULE_CALLBACK(IntPtr rule, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_PATTERN_CALLBACK(IntPtr pattern, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_MATCH_CALLBACK(IntPtr match, IntPtr userData);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr yrx_last_error();

    /// <summary>
    /// Returns the detailed message set by the C API for the most recent failed call on
    /// this thread, or null if none is available. Read this immediately after a non-success
    /// <see cref="YRX_RESULT"/> — a subsequent native call can overwrite it.
    /// </summary>
    internal static string? GetLastError()
    {
        IntPtr ptr = yrx_last_error();
        if (ptr == IntPtr.Zero)
            return null;

        int length = 0;
        while (Marshal.ReadByte(ptr, length) != 0)
            length++;

        if (length == 0)
            return null;

        byte[] buffer = new byte[length];
        Marshal.Copy(ptr, buffer, 0, length);
        return Encoding.UTF8.GetString(buffer);
    }

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void yrx_buffer_destroy(IntPtr buffer);

    // ────────────────────────────── Compiler ──────────────────────────────

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_create(uint flags, out IntPtr compiler);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void yrx_compiler_destroy(IntPtr compiler);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr yrx_compiler_build(IntPtr compiler);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_add_source_with_origin(IntPtr compiler, IntPtr src, IntPtr origin);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_add_include_dir(IntPtr compiler, IntPtr dir);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_errors_json(IntPtr compiler, out IntPtr buf);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_warnings_json(IntPtr compiler, out IntPtr buf);

    // ────────────────────────────── Rules ──────────────────────────────

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void yrx_rules_destroy(IntPtr rules);

    // ────────────────────────────── Rule inspection ──────────────────────────────

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rule_identifier(
        IntPtr rule, out IntPtr identifier, out UIntPtr length);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rule_iter_patterns(
        IntPtr rule, YRX_PATTERN_CALLBACK callback, IntPtr userData);

    // ────────────────────────────── Pattern inspection ──────────────────────────────

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_pattern_identifier(IntPtr pattern, out IntPtr identifier, out UIntPtr length);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_pattern_iter_matches(
        IntPtr pattern, YRX_MATCH_CALLBACK callback, IntPtr userData);

    // ────────────────────────────── Scanner ──────────────────────────────

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_create(IntPtr rules, out IntPtr scanner);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void yrx_scanner_destroy(IntPtr scanner);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_on_matching_rule(
        IntPtr scanner, YRX_RULE_CALLBACK callback, IntPtr userData);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_scan_file(IntPtr scanner, IntPtr path);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_scan(IntPtr scanner, byte[] data, long len);

    [DllImport("yara_x_capi", EntryPoint = "yrx_scanner_scan", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_scan_ptr(IntPtr scanner, IntPtr data, long len);
}

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

[StructLayout(LayoutKind.Sequential)]
internal struct YRX_METADATA_BYTES
{
    public UIntPtr length;
    public IntPtr data;
}

internal enum YRX_METADATA_VALUE_TYPE
{
    YRX_I64 = 0,
    YRX_F64 = 1,
    YRX_BOOLEAN = 2,
    YRX_STRING = 3,
    YRX_BYTES = 4,
}

[StructLayout(LayoutKind.Explicit)]
internal struct YRX_METADATA_VALUE
{
    [FieldOffset(0)]
    public long i64;

    [FieldOffset(0)]
    public double f64;

    [FieldOffset(0)]
    public bool boolean;

    [FieldOffset(0)]
    public IntPtr str;

    [FieldOffset(0)]
    public YRX_METADATA_BYTES bytes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct YRX_METADATA
{
    public IntPtr identifier;
    public YRX_METADATA_VALUE_TYPE value_type;
    public YRX_METADATA_VALUE value;
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
    internal delegate void YRX_IMPORTS_CALLBACK(IntPtr moduleName, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_METADATA_CALLBACK(IntPtr metadata, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_TAGS_CALLBACK(IntPtr tag, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_PATTERN_CALLBACK(IntPtr pattern, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_MATCH_CALLBACK(IntPtr match, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_SLOWEST_RULES_CALLBACK(
        IntPtr nameSpace, IntPtr ruleName, double matchTime, double evalTime, IntPtr userData);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void YRX_CONSOLE_CALLBACK(IntPtr message);


    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr yrx_last_error();

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
    internal static extern YRX_RESULT yrx_compiler_add_source(IntPtr compiler, IntPtr src);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_add_source_with_origin(IntPtr compiler, IntPtr src, IntPtr origin);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_add_include_dir(IntPtr compiler, IntPtr dir);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_ignore_module(IntPtr compiler, IntPtr module);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_ban_module(
        IntPtr compiler, IntPtr module, IntPtr errorTitle, IntPtr errorMsg);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_new_namespace(IntPtr compiler, IntPtr name);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_max_warnings(IntPtr compiler, UIntPtr n);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_define_global_str(IntPtr compiler, IntPtr identifier, IntPtr value);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_define_global_bool(IntPtr compiler, IntPtr identifier, bool value);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_define_global_int(IntPtr compiler, IntPtr identifier, long value);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_define_global_float(
        IntPtr compiler, IntPtr identifier, double value);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_errors_json(IntPtr compiler, out IntPtr buf);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_compiler_warnings_json(IntPtr compiler, out IntPtr buf);

    // ────────────────────────────── Rules ──────────────────────────────

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void yrx_rules_destroy(IntPtr rules);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int yrx_rules_count(IntPtr rules);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rules_iter(IntPtr rules, YRX_RULE_CALLBACK callback, IntPtr userData);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rules_iter_imports(
        IntPtr rules, YRX_IMPORTS_CALLBACK callback, IntPtr userData);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rules_serialize(IntPtr rules, out IntPtr buf);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rules_deserialize(byte[] data, long len, out IntPtr rules);

    // ────────────────────────────── Rule inspection ──────────────────────────────

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rule_identifier(
        IntPtr rule, out IntPtr identifier, out UIntPtr length);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rule_namespace(
        IntPtr rule, out IntPtr identifier, out UIntPtr length);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rule_iter_metadata(
        IntPtr rule, YRX_METADATA_CALLBACK callback, IntPtr userData);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_rule_iter_tags(
        IntPtr rule, YRX_TAGS_CALLBACK callback, IntPtr userData);

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
    internal static extern YRX_RESULT yrx_scanner_set_timeout(IntPtr scanner, ulong timeout);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_fast_scan(IntPtr scanner, bool yes);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_on_matching_rule(
        IntPtr scanner, YRX_RULE_CALLBACK callback, IntPtr userData);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_on_console_log(IntPtr scanner, YRX_CONSOLE_CALLBACK callback);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_scan(IntPtr scanner, byte[] data, long len);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_scan_file(IntPtr scanner, IntPtr path);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_scan_block(IntPtr scanner, long baseOffset, byte[] data, long len);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_finish(IntPtr scanner);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_iter_slowest_rules(
        IntPtr scanner, long maxResults, YRX_SLOWEST_RULES_CALLBACK callback, IntPtr userData);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_clear_profiling_data(IntPtr scanner);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_set_module_output(
        IntPtr scanner, IntPtr name, byte[] data, long length);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT
        yrx_scanner_set_module_data(IntPtr scanner, IntPtr name, byte[] data, long length);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_set_global_str(IntPtr scanner, IntPtr identifier, IntPtr value);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_set_global_bool(IntPtr scanner, IntPtr identifier, bool value);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_set_global_int(IntPtr scanner, IntPtr identifier, long value);

    [DllImport("yara_x_capi", CallingConvention = CallingConvention.Cdecl)]
    internal static extern YRX_RESULT yrx_scanner_set_global_float(IntPtr scanner, IntPtr identifier, double value);
}
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace YaraXWrapper;

public sealed class Compiler : IDisposable
{
    private IntPtr _compiler = IntPtr.Zero;

    public Compiler(CompileFlags flags = CompileFlags.None)
    {
        YRX_RESULT result = YaraXNative.yrx_compiler_create((uint)flags, out _compiler);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"Failed to create compiler: {result}");
        }
    }

    public void AddRuleFile(string filePath)
    {
        if (filePath == null) throw new ArgumentNullException(nameof(filePath));

        string fullPath = Path.GetFullPath(filePath);
        if (!File.Exists(fullPath))
        {
            throw new YrxException($"Rule file does not exist: {fullPath}");
        }

        string directory = Path.GetDirectoryName(fullPath) ?? Directory.GetCurrentDirectory();
        YRX_RESULT includeResult = YaraXNative.yrx_compiler_add_include_dir(_compiler, directory);
        if (includeResult != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"AddRuleFile: failed to register include directory '{directory}': {includeResult}");
        }

        string source = File.ReadAllText(fullPath, Encoding.UTF8);
        YRX_RESULT result = YaraXNative.yrx_compiler_add_source_with_origin(_compiler, source, fullPath);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"AddRuleFile failed for '{fullPath}': {result}");
        }
    }

    public void AddRule(string source)
    {
        if (source == null) throw new ArgumentNullException(nameof(source));

        YRX_RESULT result = YaraXNative.yrx_compiler_add_source(_compiler, source);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"AddSource failed: {result}");
        }
    }

    public void AddIncludeDir(string directory)
    {
        YRX_RESULT result = YaraXNative.yrx_compiler_add_include_dir(_compiler, directory);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"AddIncludeDir failed: {result}");
        }
    }

    public void IgnoreModule(string module)
    {
        YRX_RESULT result = YaraXNative.yrx_compiler_ignore_module(_compiler, module);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"IgnoreModule failed: {result}");
        }
    }

    public void BanModule(string module, string errorTitle, string errorMessage)
    {
        YRX_RESULT result = YaraXNative.yrx_compiler_ban_module(_compiler, module, errorTitle, errorMessage);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"BanModule failed: {result}");
        }
    }

    public void NewNamespace(string name)
    {
        YRX_RESULT result = YaraXNative.yrx_compiler_new_namespace(_compiler, name);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"NewNamespace failed: {result}");
        }
    }

    public void DefineGlobal<T>(string identifier, T value)
    {
        YRX_RESULT result = value switch
        {
            string s => YaraXNative.yrx_compiler_define_global_str(_compiler, identifier, s),
            bool b => YaraXNative.yrx_compiler_define_global_bool(_compiler, identifier, b),
            int i => YaraXNative.yrx_compiler_define_global_int(_compiler, identifier, i),
            double d => YaraXNative.yrx_compiler_define_global_float(_compiler, identifier, d),
            _ => throw new NotSupportedException($"Unsupported global type: {typeof(T).Name}"),
        };

        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"DefineGlobal failed: {result}");
        }
    }

    public CompileResult Build()
    {
        YrxError[] errors = ReadDiagnosticsJson(isErrors: true);
        YrxError[] warnings = ReadDiagnosticsJson(isErrors: false);

        IntPtr rulesPtr = YaraXNative.yrx_compiler_build(_compiler);
        var rules = new Rules(rulesPtr);

        return new CompileResult(rules, errors, warnings);
    }

    public void Dispose()
    {
        if (_compiler == IntPtr.Zero)
        {
            return;
        }

        YaraXNative.yrx_compiler_destroy(_compiler);
        _compiler = IntPtr.Zero;
    }

    private YrxError[] ReadDiagnosticsJson(bool isErrors)
    {
        IntPtr bufferPtr;
        if (isErrors)
        {
            YaraXNative.yrx_compiler_errors_json(_compiler, out bufferPtr);
        }
        else
        {
            YaraXNative.yrx_compiler_warnings_json(_compiler, out bufferPtr);
        }

        YRX_BUFFER buffer = Marshal.PtrToStructure<YRX_BUFFER>(bufferPtr);
        YrxError[] result = ParseDiagnosticsBuffer(buffer);
        YaraXNative.yrx_buffer_destroy(bufferPtr);

        return result;
    }

    private static YrxError[] ParseDiagnosticsBuffer(YRX_BUFFER buffer)
    {
        if (buffer.length.ToUInt64() <= 2)
        {
            return Array.Empty<YrxError>();
        }

        byte[] bytes = new byte[(int)buffer.length];
        Marshal.Copy(buffer.data, bytes, 0, bytes.Length);

        try
        {
            YrxError[]? parsed = JsonSerializer.Deserialize<YrxError[]>(Encoding.UTF8.GetString(bytes));
            return parsed ?? Array.Empty<YrxError>();
        }
        catch
        {
            return Array.Empty<YrxError>();
        }
    }
}
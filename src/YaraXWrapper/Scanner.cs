using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace YaraXWrapper;

/// <summary>
/// Scans data against a compiled set of <see cref="Rules"/> and returns matching rules
/// with their pattern locations.
/// </summary>
/// <remarks>
/// Not thread-safe. For parallel scanning, create one <see cref="Scanner"/> per thread —
/// multiple scanners can safely share the same <see cref="Rules"/> instance.
/// The <see cref="Rules"/> passed to the constructor must remain alive for the lifetime of this scanner.
/// </remarks>
public sealed class Scanner : IDisposable
{
    private IntPtr _scanner;
    private readonly MatchLoadOptions _loadOptions;

    // Stored in a field so the GC does not collect the delegate between scans.
    private readonly YaraXNative.YRX_RULE_CALLBACK _onMatchDelegate;

    // Replaced (not appended) at the start of every scan.
    private List<RuleMatch> _currentResults = new();

    /// <summary>Creates a scanner for the given compiled rules.</summary>
    /// <param name="loadOptions">
    /// Controls which fields are populated in each <see cref="RuleMatch"/>.
    /// Include <see cref="MatchLoadOptions.Patterns"/> to receive <see cref="PatternMatch.Offset"/>
    /// and <see cref="PatternMatch.Length"/> for each match.
    /// </param>
    public Scanner(Rules rules, MatchLoadOptions loadOptions = MatchLoadOptions.All)
    {
        if (rules == null) throw new ArgumentNullException(nameof(rules));

        _loadOptions = loadOptions;
        _onMatchDelegate = OnMatchCallback;

        YRX_RESULT createResult = YaraXNative.yrx_scanner_create(rules._pointer, out _scanner);
        if (createResult != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YaraXException($"Failed to create scanner: {createResult}");
        }

        YRX_RESULT callbackResult = YaraXNative.yrx_scanner_on_matching_rule(_scanner, _onMatchDelegate, IntPtr.Zero);
        if (callbackResult != YRX_RESULT.YRX_SUCCESS)
        {
            YaraXNative.yrx_scanner_destroy(_scanner);
            _scanner = IntPtr.Zero;
            throw new YaraXException($"Failed to register match callback: {callbackResult}");
        }
    }

    /// <summary>Aborts the scan if it takes longer than <paramref name="seconds"/> seconds.</summary>
    public void SetTimeout(ulong seconds)
    {
        YRX_RESULT result = YaraXNative.yrx_scanner_set_timeout(_scanner, seconds);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YaraXException($"SetTimeout failed: {result}");
        }
    }

    /// <summary>Scans a file and returns all matching rules.</summary>
    public IReadOnlyList<RuleMatch> Scan(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new YaraXException($"File does not exist: {filePath}");
        }

        _currentResults = new List<RuleMatch>();
        using var path = new Utf8NativeStr(filePath);
        YRX_RESULT result = YaraXNative.yrx_scanner_scan_file(_scanner, path);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YaraXException($"Scan failed: {result}");
        }

        return _currentResults;
    }

    /// <summary>Scans a byte array and returns all matching rules.</summary>
    public IReadOnlyList<RuleMatch> Scan(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));

        _currentResults = new List<RuleMatch>();
        YRX_RESULT result = YaraXNative.yrx_scanner_scan(_scanner, data, data.LongLength);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YaraXException($"Scan failed: {result}");
        }

        return _currentResults;
    }

    public void Dispose()
    {
        if (_scanner == IntPtr.Zero)
        {
            return;
        }

        YaraXNative.yrx_scanner_destroy(_scanner);
        _scanner = IntPtr.Zero;
    }

    private void OnMatchCallback(IntPtr rule, IntPtr userData)
    {
        _currentResults.Add(BuildRuleMatch(rule));
    }

    private RuleMatch BuildRuleMatch(IntPtr rule)
    {
        string identifier = string.Empty;
        string ns = string.Empty;
        var tags = new List<string>();
        var metadata = new Dictionary<string, object>();
        var patterns = new List<PatternMatch>();

        if ((_loadOptions & MatchLoadOptions.Identifier) != 0)
            identifier = ReadRuleIdentifier(rule);

        if ((_loadOptions & MatchLoadOptions.Namespace) != 0)
            ns = ReadRuleNamespace(rule);

        if ((_loadOptions & MatchLoadOptions.Tags) != 0)
            ReadRuleTags(rule, tags);

        if ((_loadOptions & MatchLoadOptions.Metadata) != 0)
            ReadRuleMetadata(rule, metadata);

        if ((_loadOptions & MatchLoadOptions.Patterns) != 0)
            ReadRulePatterns(rule, patterns);

        return new RuleMatch(identifier, ns, tags, metadata, patterns);
    }

    private static string ReadRuleIdentifier(IntPtr rule)
    {
        YRX_RESULT result = YaraXNative.yrx_rule_identifier(rule, out IntPtr ptr, out UIntPtr len);
        int length = (int)(ulong)len;
        if (result != YRX_RESULT.YRX_SUCCESS || length == 0)
            return string.Empty;

        return PtrToUtf8String(ptr, length);
    }

    private static string ReadRuleNamespace(IntPtr rule)
    {
        YRX_RESULT result = YaraXNative.yrx_rule_namespace(rule, out IntPtr ptr, out UIntPtr len);
        int length = (int)(ulong)len;
        if (result != YRX_RESULT.YRX_SUCCESS || length == 0)
            return string.Empty;

        return PtrToUtf8String(ptr, length);
    }

    private static void ReadRuleTags(IntPtr rule, List<string> tags)
    {
        YaraXNative.YRX_TAGS_CALLBACK callback = (tagPtr, _) => { tags.Add(PtrToUtf8String(tagPtr)); };
        YaraXNative.yrx_rule_iter_tags(rule, callback, IntPtr.Zero);
        GC.KeepAlive(callback);
    }

    private static void ReadRuleMetadata(IntPtr rule, Dictionary<string, object> metadata)
    {
        YaraXNative.YRX_METADATA_CALLBACK callback = (metadataPtr, _) =>
        {
            YRX_METADATA data = Marshal.PtrToStructure<YRX_METADATA>(metadataPtr);
            string key = PtrToUtf8String(data.identifier);

            switch (data.value_type)
            {
                case YRX_METADATA_VALUE_TYPE.YRX_I64: metadata[key] = data.value.i64; break;
                case YRX_METADATA_VALUE_TYPE.YRX_F64: metadata[key] = data.value.f64; break;
                case YRX_METADATA_VALUE_TYPE.YRX_BOOLEAN: metadata[key] = data.value.boolean; break;
                case YRX_METADATA_VALUE_TYPE.YRX_STRING: metadata[key] = PtrToUtf8String(data.value.str); break;
                case YRX_METADATA_VALUE_TYPE.YRX_BYTES:
                    YRX_METADATA_BYTES raw = data.value.bytes;
                    int byteLen = (int)(ulong)raw.length;
                    byte[] bytes = new byte[byteLen];
                    Marshal.Copy(raw.data, bytes, 0, byteLen);
                    metadata[key] = bytes;
                    break;
            }
        };
        YaraXNative.yrx_rule_iter_metadata(rule, callback, IntPtr.Zero);
        GC.KeepAlive(callback);
    }

    private static void ReadRulePatterns(IntPtr rule, List<PatternMatch> patterns)
    {
        YaraXNative.YRX_PATTERN_CALLBACK patternCallback = (patternPtr, _) =>
        {
            YRX_RESULT idResult = YaraXNative.yrx_pattern_identifier(
                patternPtr, out IntPtr idPtr, out UIntPtr idLen);
            int idLenInt = (int)(ulong)idLen;

            string patternId = (idResult == YRX_RESULT.YRX_SUCCESS && idLenInt > 0)
                ? PtrToUtf8String(idPtr, idLenInt)
                : string.Empty;

            YaraXNative.YRX_MATCH_CALLBACK matchCallback = (matchPtr, _) =>
            {
                YRX_MATCH m = Marshal.PtrToStructure<YRX_MATCH>(matchPtr);
                patterns.Add(new PatternMatch(patternId, m.offset, m.length));
            };

            YaraXNative.yrx_pattern_iter_matches(patternPtr, matchCallback, IntPtr.Zero);
            GC.KeepAlive(matchCallback);
        };

        YaraXNative.yrx_rule_iter_patterns(rule, patternCallback, IntPtr.Zero);
        GC.KeepAlive(patternCallback);
    }

    private static string PtrToUtf8String(IntPtr ptr)
    {
        if (ptr == IntPtr.Zero)
            return string.Empty;

        int length = 0;
        while (Marshal.ReadByte(ptr, length) != 0)
            length++;

        return PtrToUtf8String(ptr, length);
    }

    private static string PtrToUtf8String(IntPtr ptr, int length)
    {
        if (ptr == IntPtr.Zero || length <= 0)
            return string.Empty;

        byte[] buffer = new byte[length];
        Marshal.Copy(ptr, buffer, 0, length);
        return Encoding.UTF8.GetString(buffer);
    }
}
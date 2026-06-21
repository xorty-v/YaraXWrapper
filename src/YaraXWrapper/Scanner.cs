using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace YaraXWrapper;

public sealed class Scanner : IDisposable
{
    private IntPtr _scanner;
    private readonly MatchLoadOptions _loadOptions;

    // The callback registered with yrx_scanner_on_matching_rule is stored by the native
    // scanner and called on every match. The delegate MUST be kept alive in a field —
    // a method-group or lambda passed directly can be collected by the GC between scans.
    private readonly YaraXNative.YRX_RULE_CALLBACK _onMatchDelegate;

    // Populated during each scan; replaced (not appended) at the start of every new scan.
    private List<RuleMatch> _currentResults = new();

    public Scanner(Rules rules, MatchLoadOptions loadOptions = MatchLoadOptions.All)
    {
        if (rules == null) throw new ArgumentNullException(nameof(rules));

        _loadOptions = loadOptions;
        _onMatchDelegate = OnMatchCallback;

        YRX_RESULT createResult = YaraXNative.yrx_scanner_create(rules._pointer, out _scanner);
        if (createResult != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"Failed to create scanner: {createResult}");
        }

        YRX_RESULT callbackResult = YaraXNative.yrx_scanner_on_matching_rule(_scanner, _onMatchDelegate, IntPtr.Zero);
        if (callbackResult != YRX_RESULT.YRX_SUCCESS)
        {
            YaraXNative.yrx_scanner_destroy(_scanner);
            _scanner = IntPtr.Zero;
            throw new YrxException($"Failed to register match callback: {callbackResult}");
        }
    }

    public void SetTimeout(ulong seconds)
    {
        YRX_RESULT result = YaraXNative.yrx_scanner_set_timeout(_scanner, seconds);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"SetTimeout failed: {result}");
        }
    }

    public IReadOnlyList<RuleMatch> Scan(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new YrxException($"File does not exist: {filePath}");
        }

        _currentResults = new List<RuleMatch>();
        YRX_RESULT result = YaraXNative.yrx_scanner_scan_file(_scanner, filePath);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"Scan failed: {result}");
        }

        return _currentResults;
    }

    public IReadOnlyList<RuleMatch> Scan(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (data.Length == 0) throw new YrxException("Data buffer is empty.");

        _currentResults = new List<RuleMatch>();
        YRX_RESULT result = YaraXNative.yrx_scanner_scan(_scanner, data, data.LongLength);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"Scan failed: {result}");
        }

        return _currentResults;
    }

    public IReadOnlyList<RuleMatch> ScanInBlocks(string filePath, int blockSize)
    {
        if (!File.Exists(filePath))
        {
            throw new YrxException($"File does not exist: {filePath}");
        }

        _currentResults = new List<RuleMatch>();

        using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        {
            long offset = 0;
            byte[] buffer = new byte[blockSize];

            while (offset < stream.Length)
            {
                stream.Seek(offset, SeekOrigin.Begin);
                int bytesRead = stream.Read(buffer, 0, blockSize);
                if (bytesRead == 0)
                {
                    break;
                }

                // 'offset' is the byte offset of this block in the overall data — NOT a block index.
                YRX_RESULT blockResult = YaraXNative.yrx_scanner_scan_block(_scanner, offset, buffer, bytesRead);
                if (blockResult != YRX_RESULT.YRX_SUCCESS)
                {
                    throw new YrxException($"ScanBlock failed at offset 0x{offset:X}: {blockResult}");
                }

                offset += bytesRead;
            }
        }

        YRX_RESULT finalResult = YaraXNative.yrx_scanner_finish(_scanner);
        if (finalResult != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"ScanBlock finalization failed: {finalResult}");
        }

        return _currentResults;
    }

    public IReadOnlyList<SlowRuleInfo> GetSlowestRules(long maxResults)
    {
        var slowestRules = new List<SlowRuleInfo>();

        YaraXNative.YRX_SLOWEST_RULES_CALLBACK callback =
            (nsPtr, rulePtr, matchTime, evalTime, _) =>
            {
                var ns = Utf8Marshal.PtrToString(nsPtr);
                var ruleName = Utf8Marshal.PtrToString(rulePtr);
                slowestRules.Add(new SlowRuleInfo(ns, ruleName, matchTime, evalTime));
            };

        YRX_RESULT result = YaraXNative.yrx_scanner_iter_slowest_rules(_scanner, maxResults, callback, IntPtr.Zero);
        GC.KeepAlive(callback);

        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"GetSlowestRules failed: {result}");
        }

        return slowestRules;
    }

    public void SetGlobal(string identifier, string value)
    {
        YRX_RESULT result = YaraXNative.yrx_scanner_set_global_str(_scanner, identifier, value);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"SetGlobal failed: {result}");
        }
    }

    public void SetGlobal(string identifier, bool value)
    {
        YRX_RESULT result = YaraXNative.yrx_scanner_set_global_bool(_scanner, identifier, value);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"SetGlobal failed: {result}");
        }
    }

    public void SetGlobal(string identifier, int value)
    {
        YRX_RESULT result = YaraXNative.yrx_scanner_set_global_int(_scanner, identifier, value);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"SetGlobal failed: {result}");
        }
    }

    public void SetGlobal(string identifier, double value)
    {
        YRX_RESULT result = YaraXNative.yrx_scanner_set_global_float(_scanner, identifier, value);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"SetGlobal failed: {result}");
        }
    }

    public void ClearProfilingData()
    {
        YRX_RESULT result = YaraXNative.yrx_scanner_clear_profiling_data(_scanner);
        if (result != YRX_RESULT.YRX_SUCCESS)
        {
            throw new YrxException($"ClearProfilingData failed: {result}");
        }
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
        RuleMatch match = BuildRuleMatch(rule);
        _currentResults.Add(match);
    }

    private RuleMatch BuildRuleMatch(IntPtr rule)
    {
        string identifier = string.Empty;
        string ns = string.Empty;
        var tags = new List<string>();
        var metadata = new Dictionary<string, object>();
        var patterns = new List<PatternMatch>();

        if ((_loadOptions & MatchLoadOptions.Identifier) != 0)
        {
            identifier = ReadRuleIdentifier(rule);
        }

        if ((_loadOptions & MatchLoadOptions.Namespace) != 0)
        {
            ns = ReadRuleNamespace(rule);
        }

        if ((_loadOptions & MatchLoadOptions.Tags) != 0)
        {
            ReadRuleTags(rule, tags);
        }

        if ((_loadOptions & MatchLoadOptions.Metadata) != 0)
        {
            ReadRuleMetadata(rule, metadata);
        }

        if ((_loadOptions & MatchLoadOptions.Patterns) != 0)
        {
            ReadRulePatterns(rule, patterns);
        }

        return new RuleMatch(identifier, ns, tags, metadata, patterns);
    }

    private static string ReadRuleIdentifier(IntPtr rule)
    {
        YRX_RESULT result = YaraXNative.yrx_rule_identifier(rule, out IntPtr ptr, out UIntPtr len);
        int length = (int)(ulong)len;
        if (result != YRX_RESULT.YRX_SUCCESS || length == 0)
        {
            return string.Empty;
        }

        return Utf8Marshal.PtrToString(ptr, length);
    }

    private static string ReadRuleNamespace(IntPtr rule)
    {
        YRX_RESULT result = YaraXNative.yrx_rule_namespace(rule, out IntPtr ptr, out UIntPtr len);
        int length = (int)(ulong)len;
        if (result != YRX_RESULT.YRX_SUCCESS || length == 0)
        {
            return string.Empty;
        }

        return Utf8Marshal.PtrToString(ptr, length);
    }

    private static void ReadRuleTags(IntPtr rule, List<string> tags)
    {
        YaraXNative.YRX_TAGS_CALLBACK callback = (tagPtr, _) => { tags.Add(Utf8Marshal.PtrToString(tagPtr)); };
        YaraXNative.yrx_rule_iter_tags(rule, callback, IntPtr.Zero);
        GC.KeepAlive(callback);
    }

    private static void ReadRuleMetadata(IntPtr rule, Dictionary<string, object> metadata)
    {
        YaraXNative.YRX_METADATA_CALLBACK callback = (metadataPtr, _) =>
        {
            YRX_METADATA data = Marshal.PtrToStructure<YRX_METADATA>(metadataPtr);
            string key = Utf8Marshal.PtrToString(data.identifier);

            switch (data.value_type)
            {
                case YRX_METADATA_VALUE_TYPE.YRX_I64:
                    metadata[key] = data.value.i64;
                    break;
                case YRX_METADATA_VALUE_TYPE.YRX_F64:
                    metadata[key] = data.value.f64;
                    break;
                case YRX_METADATA_VALUE_TYPE.YRX_BOOLEAN:
                    metadata[key] = data.value.boolean;
                    break;
                case YRX_METADATA_VALUE_TYPE.YRX_STRING:
                    metadata[key] = Utf8Marshal.PtrToString(data.value.str);
                    break;
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
                ? Utf8Marshal.PtrToString(idPtr, idLenInt)
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

    private static class Utf8Marshal
    {
        internal static string PtrToString(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
            {
                return string.Empty;
            }

            int length = 0;
            while (Marshal.ReadByte(ptr, length) != 0)
            {
                length++;
            }

            return PtrToString(ptr, length);
        }

        internal static string PtrToString(IntPtr ptr, int length)
        {
            if (ptr == IntPtr.Zero || length <= 0)
            {
                return string.Empty;
            }

            byte[] buffer = new byte[length];
            Marshal.Copy(ptr, buffer, 0, length);
            return Encoding.UTF8.GetString(buffer);
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
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
    public Scanner(Rules rules, MatchLoadOptions loadOptions = MatchLoadOptions.Identifier | MatchLoadOptions.Patterns)
    {
        if (rules == null) throw new ArgumentNullException(nameof(rules));

        _loadOptions = loadOptions;
        _onMatchDelegate = OnMatchCallback;

        YRX_RESULT createResult = YaraXNative.yrx_scanner_create(rules._pointer, out _scanner);
        if (createResult != YRX_RESULT.YRX_SUCCESS)
        {
            throw YaraXException.FromResult("Failed to create scanner", createResult);
        }

        YRX_RESULT callbackResult = YaraXNative.yrx_scanner_on_matching_rule(_scanner, _onMatchDelegate, IntPtr.Zero);
        if (callbackResult != YRX_RESULT.YRX_SUCCESS)
        {
            YaraXException ex = YaraXException.FromResult("Failed to register match callback", callbackResult);
            YaraXNative.yrx_scanner_destroy(_scanner);
            _scanner = IntPtr.Zero;
            throw ex;
        }
    }

    /// <summary>
    /// Scans a file via our own read-only (FILE_MAP_READ) memory mapping instead of letting the
    /// native library map the file itself. YARA-X's own file mapping is copy-on-write
    /// (FILE_MAP_COPY), which requires Windows to reserve pagefile-backed commit for the entire
    /// view up front; a plain read-only mapping does not, since its pages are backed directly by
    /// the file. This avoids the transient ERROR_COMMITMENT_LIMIT ("paging file too small") that
    /// <see cref="Scan(string)"/> can hit under memory pressure, for a file of any size.
    /// </summary>
    public unsafe IReadOnlyList<RuleMatch> ScanMapped(string filePath)
    {
        FileInfo info = new(filePath);
        if (!info.Exists)
        {
            throw new YaraXException($"File does not exist: {filePath}");
        }

        if (info.Length == 0)
        {
            return _currentResults = new List<RuleMatch>();
        }

        using MemoryMappedFile mmf = MemoryMappedFile.CreateFromFile(
            filePath, FileMode.Open, mapName: null, capacity: 0, MemoryMappedFileAccess.Read);
        using MemoryMappedViewAccessor accessor = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);

        byte* ptr = null;
        accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
        try
        {
            _currentResults = new List<RuleMatch>();
            YRX_RESULT result = YaraXNative.yrx_scanner_scan_ptr(_scanner, (IntPtr)ptr, info.Length);
            if (result != YRX_RESULT.YRX_SUCCESS)
            {
                throw YaraXException.FromResult($"Scan failed for '{filePath}' (mapped)", result);
            }

            return _currentResults;
        }
        finally
        {
            accessor.SafeMemoryMappedViewHandle.ReleasePointer();
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
        _currentResults.Add(BuildRuleMatch(rule));
    }

    private RuleMatch BuildRuleMatch(IntPtr rule)
    {
        string identifier = string.Empty;
        var patterns = new List<PatternMatch>();

        if ((_loadOptions & MatchLoadOptions.Identifier) != 0)
            identifier = ReadRuleIdentifier(rule);

        if ((_loadOptions & MatchLoadOptions.Patterns) != 0)
            ReadRulePatterns(rule, patterns);

        return new RuleMatch(identifier, patterns);
    }

    private static string ReadRuleIdentifier(IntPtr rule)
    {
        YRX_RESULT result = YaraXNative.yrx_rule_identifier(rule, out IntPtr ptr, out UIntPtr len);
        int length = (int)(ulong)len;
        if (result != YRX_RESULT.YRX_SUCCESS || length == 0)
            return string.Empty;

        return PtrToUtf8String(ptr, length);
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

    private static string PtrToUtf8String(IntPtr ptr, int length)
    {
        if (ptr == IntPtr.Zero || length <= 0)
            return string.Empty;

        byte[] buffer = new byte[length];
        Marshal.Copy(ptr, buffer, 0, length);
        return Encoding.UTF8.GetString(buffer);
    }
}

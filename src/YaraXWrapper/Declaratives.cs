using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace YaraXWrapper;

/// <summary>Flags that control compiler behavior. Can be combined.</summary>
[Flags]
public enum CompileFlags : uint
{
    None = 0,
    RelaxedReSyntax = 2,
}

/// <summary>
/// Controls which fields are populated in each <see cref="RuleMatch"/> during a scan.
/// Use the minimum set needed to reduce per-match allocations.
/// </summary>
/// <remarks>
/// <see cref="Patterns"/> must be included to access <see cref="PatternMatch.Offset"/>
/// and <see cref="PatternMatch.Length"/>.
/// </remarks>
[Flags]
public enum MatchLoadOptions
{
    None = 0,
    Patterns = 4,
    Identifier = 16,
}

/// <summary>Thrown when a native YARA-X operation fails with an unexpected error code.</summary>
public sealed class YaraXException : Exception
{
    public YaraXException(string message) : base(message) { }

    /// <summary>
    /// Builds a <see cref="YaraXException"/> for a failed native call, appending the
    /// detailed message from <c>yrx_last_error()</c> when the C API provided one.
    /// </summary>
    internal static YaraXException FromResult(string context, YRX_RESULT result)
    {
        string? detail = YaraXNative.GetLastError();
        return string.IsNullOrEmpty(detail)
            ? new YaraXException($"{context}: {result}")
            : new YaraXException($"{context}: {result} — {detail}");
    }
}

/// <summary>A compile-time diagnostic (error or warning) produced by the YARA-X compiler.</summary>
public sealed class CompileError
{
    [JsonPropertyName("type")]
    public string? Type { get; set; }

    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("title")]
    public string? Title { get; set; }

    [JsonPropertyName("text")]
    public string? Text { get; set; }

    [JsonExtensionData]
    public Dictionary<string, object?>? ExtensionData { get; set; }
}

/// <summary>
/// The result of <see cref="Compiler.Build"/>.
/// <see cref="Rules"/> always contains the successfully compiled rules and is never null,
/// but may have zero rules if every source had errors.
/// Invalid sources are not silently discarded — they appear in <see cref="Errors"/>.
/// </summary>
public readonly struct CompileResult
{
    public Rules Rules { get; }
    public IReadOnlyList<CompileError> Errors { get; }
    public IReadOnlyList<CompileError> Warnings { get; }

    internal CompileResult(Rules rules, CompileError[] errors, CompileError[] warnings)
    {
        Rules = rules;
        Errors = errors;
        Warnings = warnings;
    }
}

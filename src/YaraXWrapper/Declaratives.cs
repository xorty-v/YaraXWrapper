using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace YaraXWrapper;

/// <summary>Flags that control compiler behavior. Can be combined.</summary>
[Flags]
public enum CompileFlags : uint
{
    None = 0,
    ColorizeErrors = 1,
    RelaxedReSyntax = 2,
    ErrorOnSlowPattern = 4,
    ErrorOnSlowLoop = 8,
    EnableConditionOptimization = 16,
    DisableIncludes = 32,
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
    Metadata = 1,
    Tags = 2,
    Patterns = 4,
    Namespace = 8,
    Identifier = 16,
    All = Metadata | Tags | Patterns | Namespace | Identifier,
}

/// <summary>Thrown when a native YARA-X operation fails with an unexpected error code.</summary>
public sealed class YaraXException : Exception
{
    public YaraXException(string message) : base(message) { }
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

internal sealed class SlowRuleInfo
{
    public string Namespace { get; }
    public string Rule { get; }
    public double MatchTime { get; }
    public double EvalTime { get; }

    internal SlowRuleInfo(string ns, string rule, double matchTime, double evalTime)
    {
        Namespace = ns;
        Rule = rule;
        MatchTime = matchTime;
        EvalTime = evalTime;
    }
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

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace YaraXWrapper;

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

public sealed class YrxException : Exception
{
    public YrxException(string message) : base(message) { }
}

public sealed class YrxError
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

public sealed class SlowRuleInfo
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

public readonly struct CompileResult
{
    public Rules Rules { get; }
    public IReadOnlyList<YrxError> Errors { get; }
    public IReadOnlyList<YrxError> Warnings { get; }

    internal CompileResult(Rules rules, YrxError[] errors, YrxError[] warnings)
    {
        Rules = rules;
        Errors = errors;
        Warnings = warnings;
    }
}

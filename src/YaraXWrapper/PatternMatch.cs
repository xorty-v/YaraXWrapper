using System.Collections.Generic;

namespace YaraXWrapper;

/// <summary>
/// A single occurrence of a matched pattern within scanned data.
/// Only populated when <see cref="MatchLoadOptions.Patterns"/> is set on the <see cref="Scanner"/>.
/// </summary>
public sealed class PatternMatch
{
    /// <summary>Pattern identifier as declared in the rule, e.g. <c>$a</c>.</summary>
    public string Identifier { get; }

    /// <summary>Byte offset of this match within the scanned data.</summary>
    public ulong Offset { get; }

    /// <summary>Byte length of this match.</summary>
    public ulong Length { get; }

    internal PatternMatch(string identifier, ulong offset, ulong length)
    {
        Identifier = identifier;
        Offset = offset;
        Length = length;
    }
}

/// <summary>
/// A rule that matched during a scan.
/// Only fields requested via <see cref="MatchLoadOptions"/> are populated; others are empty.
/// </summary>
public sealed class RuleMatch
{
    public string Identifier { get; }
    public string Namespace { get; }
    public IReadOnlyList<string> Tags { get; }
    public IReadOnlyDictionary<string, object> Metadata { get; }

    /// <summary>
    /// Pattern matches for this rule.
    /// Empty unless <see cref="MatchLoadOptions.Patterns"/> was set when creating the <see cref="Scanner"/>.
    /// </summary>
    public IReadOnlyList<PatternMatch> Patterns { get; }

    internal RuleMatch(
        string identifier,
        string ns,
        IReadOnlyList<string> tags,
        IReadOnlyDictionary<string, object> metadata,
        IReadOnlyList<PatternMatch> patterns)
    {
        Identifier = identifier;
        Namespace = ns;
        Tags = tags;
        Metadata = metadata;
        Patterns = patterns;
    }
}

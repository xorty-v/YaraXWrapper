using System.Collections.Generic;

namespace YaraXWrapper;

public sealed class PatternMatch
{
    public string Identifier { get; }
    public ulong Offset { get; }
    public ulong Length { get; }

    internal PatternMatch(string identifier, ulong offset, ulong length)
    {
        Identifier = identifier;
        Offset = offset;
        Length = length;
    }
}

public sealed class RuleMatch
{
    public string Identifier { get; }
    public string Namespace { get; }
    public IReadOnlyList<string> Tags { get; }
    public IReadOnlyDictionary<string, object> Metadata { get; }
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

# YaraXWrapper

.NET Standard 2.0 wrapper for the [YARA-X](https://github.com/VirusTotal/yara-x) C API (bundled: `yara_x_capi` 1.18.0).

## Install

```
dotnet add package YaraXWrapper
```

## Quick start

```csharp
using YaraXWrapper;

using var compiler = new Compiler();
compiler.AddRuleFile(@"rules\malware.yar");   // plain .yar or index file with includes

CompileResult result = compiler.Build();

// Invalid rules are not silently discarded — they appear in Errors.
foreach (CompileError err in result.Errors)
    Console.WriteLine($"[{err.Code}] {err.Title}: {err.Text}");

// MatchLoadOptions.Patterns is required to get offset and length per match.
using var scanner = new Scanner(result.Rules, MatchLoadOptions.Identifier | MatchLoadOptions.Patterns);

foreach (RuleMatch match in scanner.Scan(@"C:\sample.exe"))
{
    Console.WriteLine($"Rule: {match.Identifier}");
    foreach (PatternMatch pm in match.Patterns)
        Console.WriteLine($"  {pm.Identifier}  offset=0x{pm.Offset:X}  length={pm.Length}");
}
```

## Handling compile errors

`AddRuleFile` and `AddRule` do not throw on syntax errors. Errors accumulate and are returned
in `CompileResult.Errors` after `Build()`. Rules from other files that compiled successfully
are still available in `CompileResult.Rules`.

```csharp
foreach (string path in ruleFiles)
    compiler.AddRuleFile(path);   // keeps going even if a file has errors

CompileResult result = compiler.Build();

foreach (CompileError err in result.Errors)
    logger.Warn($"[{err.Code}] {err.Title}");

if (result.Rules.Count > 0)
    ScanWith(result.Rules);
```

## Lifecycle

`Compiler` is single-use — `Build()` consumes it. Dispose all three objects when done:

```csharp
using var compiler = new Compiler();
// ... add rules ...
CompileResult result = compiler.Build();

using var rules   = result.Rules;
using var scanner = new Scanner(rules, MatchLoadOptions.Identifier | MatchLoadOptions.Patterns);
// ... scan ...
```

`Rules` must remain alive for the entire lifetime of any `Scanner` created from it.

## Thread safety

`Scanner` is not thread-safe. For parallel scanning, create one `Scanner` per thread.
Multiple scanners can share the same `Rules` instance safely.

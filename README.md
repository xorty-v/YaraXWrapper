# YaraXWrapper

.NET Standard 2.0 wrapper for the [YARA-X](https://github.com/VirusTotal/yara-x) C API (`yara_x_capi` 1.18.0).

## Quick start

```csharp
using YaraXWrapper;

// Compile
using var compiler = new Compiler();
compiler.AddRuleFile(@"rules\index.yar");   // plain .yar or index file with includes
CompileResult compiled = compiler.Build();

if (compiled.Errors.Count > 0)
{
    foreach (var err in compiled.Errors)
        Console.WriteLine($"[{err.Code}] {err.Title}");
    return;
}

// Scan
using var rules   = compiled.Rules;
using var scanner = new Scanner(rules, MatchLoadOptions.Identifier | MatchLoadOptions.Patterns);

foreach (RuleMatch match in scanner.Scan(@"C:\target.exe"))
{
    Console.WriteLine($"Rule: {match.Identifier}");
    foreach (PatternMatch pm in match.Patterns)
        Console.WriteLine($"  {pm.Identifier}  offset={pm.Offset}  length={pm.Length}");
}
```

## API

### `Compiler`

| Method | Description |
|---|---|
| `AddRuleFile(string path)` | Compile a `.yar` file; auto-registers its directory for `include` resolution. Works for both plain rule files and index files. |
| `AddRule(string source)` | Compile YARA source from a string. |
| `AddIncludeDir(string dir)` | Add an extra include search directory. |
| `NewNamespace(string name)` | Subsequent rules go into this namespace. |
| `DefineGlobal<T>(string id, T value)` | Define a global variable (`bool`, `int`, `double`, `string`). |
| `IgnoreModule(string name)` | Silently ignore an unknown module. |
| `BanModule(string name, ...)` | Reject rules that import a module. |
| `Build()` | Returns `CompileResult` with `Rules`, `Errors`, and `Warnings`. |

### `Scanner`

| Method | Description |
|---|---|
| `Scan(string filePath)` | Scan a file by path. |
| `Scan(byte[] data)` | Scan a byte array. |
| `ScanInBlocks(string filePath, int blockSize)` | Stream-scan a large file in blocks. |
| `SetTimeout(ulong seconds)` | Abort scan after N seconds. |
| `SetGlobal(string id, T value)` | Override a global variable for this scanner. |
| `GetSlowestRules(long max)` | Return profiling data for the slowest rules. |

### `MatchLoadOptions`

Controls what data is populated in each `RuleMatch`. Use the minimum needed to reduce allocations.

```csharp
[Flags]
public enum MatchLoadOptions
{
    None       = 0,
    Metadata   = 1,
    Tags       = 2,
    Patterns   = 4,   // includes Offset + Length per match
    Namespace  = 8,
    Identifier = 16,
    All        = Metadata | Tags | Patterns | Namespace | Identifier,
}
```

### `CompileFlags`

```csharp
[Flags]
public enum CompileFlags : uint
{
    None                        = 0,
    ColorizeErrors              = 1,
    RelaxedReSyntax             = 2,
    ErrorOnSlowPattern          = 4,
    ErrorOnSlowLoop             = 8,
    EnableConditionOptimization = 16,
    DisableIncludes             = 32,
}
```
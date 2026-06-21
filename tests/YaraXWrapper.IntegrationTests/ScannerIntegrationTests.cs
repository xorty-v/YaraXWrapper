using System.Text;

namespace YaraXWrapper.IntegrationTests;

public sealed class ScannerIntegrationTests : IDisposable
{
    private readonly string _tempDir;

    public ScannerIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "YaraXWrapperTests_" + Path.GetRandomFileName());
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // ignored
        }
    }

    private string WriteTextFile(string relativePath, string content)
    {
        string fullPath = Path.Combine(_tempDir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        return fullPath;
    }

    private string WriteBinaryFile(string relativePath, byte[] content)
    {
        string fullPath = Path.Combine(_tempDir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllBytes(fullPath, content);
        return fullPath;
    }

    [Fact]
    public void AddRuleFile_SimpleRule_MatchesWithCorrectOffsetAndLength()
    {
        // Arrange
        const string rule = """
                            rule FindEvil {
                                strings:
                                    $a = "evil"
                                condition:
                                    $a
                            }
                            """;

        byte[] scanData = "hello evil world"u8.ToArray();

        string yarPath = WriteTextFile("rule.yar", rule);
        string scanPath = WriteBinaryFile("target.bin", scanData);

        // Act
        using var compiler = new Compiler();
        compiler.AddRuleFile(yarPath);
        CompileResult compiled = compiler.Build();
        Assert.Empty(compiled.Errors);

        using var rules = compiled.Rules;
        using var scanner = new Scanner(rules, MatchLoadOptions.Identifier | MatchLoadOptions.Patterns);
        var matches = scanner.Scan(scanPath);

        // Assert
        Assert.Single(matches);
        RuleMatch match = matches[0];
        Assert.Equal("FindEvil", match.Identifier);

        PatternMatch pm = Assert.Single(match.Patterns);
        Assert.Equal("$a", pm.Identifier);
        Assert.Equal(6UL, pm.Offset);
        Assert.Equal(4UL, pm.Length);
    }

    [Fact]
    public void AddRuleFile_IndexFileWithIncludes_ResolvesIncludeAndMatches()
    {
        // Arrange
        const string includedRule = """
                                    rule FindSecret {
                                        strings:
                                            $s = "secret"
                                        condition:
                                            $s
                                    }
                                    """;

        const string indexSource = """include "./rules/included.yar" """;


        byte[] scanData = "abc secret xyz"u8.ToArray();

        WriteTextFile(Path.Combine("idx", "rules", "included.yar"), includedRule);
        string indexPath = WriteTextFile(Path.Combine("idx", "index.yar"), indexSource);
        string scanPath = WriteBinaryFile("target.bin", scanData);

        // Act
        using var compiler = new Compiler();
        compiler.AddRuleFile(indexPath);
        CompileResult compiled = compiler.Build();
        Assert.Empty(compiled.Errors);

        using var rules = compiled.Rules;
        using var scanner = new Scanner(rules, MatchLoadOptions.Identifier | MatchLoadOptions.Patterns);
        var matches = scanner.Scan(scanPath);

        // Assert
        Assert.Single(matches);
        RuleMatch match = matches[0];
        Assert.Equal("FindSecret", match.Identifier);

        PatternMatch pm = Assert.Single(match.Patterns);
        Assert.Equal("$s", pm.Identifier);
        Assert.Equal(4UL, pm.Offset);
        Assert.Equal(6UL, pm.Length);
    }

    [Fact]
    public void AddRuleFile_RegularRuleFile_CompilesAndMatches()
    {
        // Arrange
        const string rule = """
                            rule FindToken {
                                strings:
                                    $t = "TOKEN"
                                condition:
                                    $t
                            }
                            """;


        byte[] scanData = "prefix TOKEN suffix"u8.ToArray();

        string yarPath = WriteTextFile("rule.yar", rule);
        string scanPath = WriteBinaryFile("target.bin", scanData);

 
        using var compiler = new Compiler();
        compiler.AddRuleFile(yarPath);
        CompileResult compiled = compiler.Build();
        Assert.Empty(compiled.Errors);

        using var rules = compiled.Rules;
        using var scanner = new Scanner(rules, MatchLoadOptions.Identifier | MatchLoadOptions.Patterns);
        var matches = scanner.Scan(scanPath);

        // Assert
        Assert.Single(matches);
        Assert.Equal("FindToken", matches[0].Identifier);
        Assert.Equal(7UL, matches[0].Patterns[0].Offset);
        Assert.Equal(5UL, matches[0].Patterns[0].Length);
    }

    [Fact]
    public void Scan_CalledTwiceWithSameScanner_DoesNotAccumulatePreviousResults()
    {
        // Arrange
        const string rule = """
                            rule FindEvil {
                                strings:
                                    $a = "evil"
                                condition:
                                    $a
                            }
                            """;

        string yarPath = WriteTextFile("rule.yar", rule);

        using var compiler = new Compiler();
        compiler.AddRuleFile(yarPath);
        CompileResult compiled = compiler.Build();
        Assert.Empty(compiled.Errors);

        using var rules = compiled.Rules;
        using var scanner = new Scanner(rules, MatchLoadOptions.Identifier);

        // Act & Assert — first scan matches, second scan must not inherit those results
        var firstResults = scanner.Scan("some evil data"u8.ToArray());
        Assert.Single(firstResults);

        var secondResults = scanner.Scan("clean data here"u8.ToArray());
        Assert.Empty(secondResults);
    }

    [Fact]
    public void AddRuleFile_SyntaxError_ErrorContainsOriginFilePath()
    {
        // Arrange — empty condition body is a syntax error
        const string brokenRule = """
                                  rule BrokenSyntax {
                                      condition:
                                  }
                                  """;

        string yarPath = WriteTextFile("bad.yar", brokenRule);
        using var compiler = new Compiler();

        // Act
        try
        {
            compiler.AddRuleFile(yarPath);
        }
        catch (YrxException ex)
        {
            Assert.Contains("bad.yar", ex.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        // Assert — add_source accumulated the error; retrieve it via Build()
        CompileResult compiled = compiler.Build();
        Assert.NotEmpty(compiled.Errors);

        bool originInText = compiled.Errors.Any(e =>
            e.Text != null && e.Text.Contains("bad.yar", StringComparison.OrdinalIgnoreCase));
        Assert.True(originInText,
            "Expected at least one error's 'text' to reference the origin file 'bad.yar'.\n" +
            "Errors: " + string.Join("\n", compiled.Errors.Select(e => e.Text ?? e.Title ?? "(no text)")));
    }

    [Fact]
    public void AddRuleFile_UnknownIdentifier_ReturnsDiagnosticWithCodeAndTitle()
    {
        // Arrange — valid syntax, unknown identifier in condition (YARA-X error E009)
        const string brokenRule = """
                                  rule BrokenRule {
                                      strings:
                                          $a = "test"
                                      condition:
                                          unknown_identifier
                                  }
                                  """;

        string yarPath = WriteTextFile("invalid.yar", brokenRule);
        using var compiler = new Compiler();

        // Act
        try
        {
            compiler.AddRuleFile(yarPath);
        }
        catch (YrxException ex)
        {
            Assert.Contains("invalid.yar", ex.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        // Assert
        CompileResult compiled = compiler.Build();
        Assert.NotEmpty(compiled.Errors);

        YrxError error = compiled.Errors[0];
        Assert.NotNull(error.Code);
        Assert.NotNull(error.Title);

        string allText = string.Join(" ", new[] { error.Code, error.Title, error.Text }.Where(s => s != null)!);
        Assert.True(
            allText.Contains("unknown_identifier", StringComparison.OrdinalIgnoreCase),
            $"Expected error info to mention 'unknown_identifier'. Got: {allText}");
    }
}
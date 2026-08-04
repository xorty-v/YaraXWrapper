using System;

namespace YaraXWrapper;

/// <summary>
/// A compiled set of YARA-X rules produced by <see cref="Compiler.Build"/>.
/// Dispose when no longer needed to free the underlying native object.
/// </summary>
/// <remarks>
/// A <see cref="Rules"/> instance must remain alive for the entire lifetime of any
/// <see cref="Scanner"/> created from it.
/// </remarks>
public sealed class Rules : IDisposable
{
    internal IntPtr _pointer = IntPtr.Zero;

    internal Rules(IntPtr rulesPtr)
    {
        _pointer = rulesPtr;
    }

    public void Dispose()
    {
        if (_pointer == IntPtr.Zero)
        {
            return;
        }

        YaraXNative.yrx_rules_destroy(_pointer);
        _pointer = IntPtr.Zero;
    }
}

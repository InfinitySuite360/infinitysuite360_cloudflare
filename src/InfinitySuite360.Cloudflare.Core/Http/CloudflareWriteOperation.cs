namespace InfinitySuite360.Cloudflare.Http;

/// <summary>
/// Marks the reads a write method makes to prepare its change (0.9.1, L-2): the member list before a removal, the current state before an Ensure or an
/// upsert. The resource clients start the mark when they check the write guard (<c>EnsureWritable</c>); the connection then counts the reads of the
/// same asynchronous flow against the write share of the budget, and ends the mark with the first write it sends. Every public method that checks the
/// write guard is an <c>async</c> method, so the mark never reaches the caller's flow.
/// </summary>
internal static class CloudflareWriteOperation
{
    private sealed class Mark
    {
        public volatile bool Active = true;
    }

    private static readonly AsyncLocal<Mark?> Current = new();

    /// <summary>Starts a write operation in the current asynchronous flow.</summary>
    public static void Begin() => Current.Value = new Mark();

    /// <summary>True while the current flow prepares a write that has not been sent yet.</summary>
    public static bool Active => Current.Value is { Active: true };

    /// <summary>The write was sent: later reads of the flow are reads again.</summary>
    public static void End()
    {
        if (Current.Value is { } mark) mark.Active = false;
    }
}

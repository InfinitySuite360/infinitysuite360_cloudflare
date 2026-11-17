using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text;

namespace InfinitySuite360.Cloudflare.Http;

/// <summary>
/// Settings of the shared request budget per API token (0.9.0). Cloudflare allows 1200 requests in five minutes per user or token
/// (<see href="https://developers.cloudflare.com/fundamentals/api/reference/limits/">API rate limits</see>, retrieved 17.11.2026); a token that exceeds it
/// is blocked with HTTP 429 for the rest of the window. The budget counts every request of all clients that share the token and delays a request
/// <b>before</b> it is sent once the share for its kind is used up, instead of running into 429.
/// </summary>
public sealed class CloudflareRateBudgetOptions
{
    /// <summary>Count and delay requests (default <c>true</c>). Only used where a <see cref="CloudflareRateBudgetRegistry"/> is in place (dependency injection, <see cref="ICloudflareClientFactory"/>).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Cloudflare's limit per window (default 1200).</summary>
    public int RequestsPerWindow { get; set; } = 1200;

    /// <summary>Length of the window (default five minutes).</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Share of <see cref="RequestsPerWindow"/> that reads may use (default 0.8 = 960): watchers and dashboards never eat the headroom of a write.</summary>
    public double ReadShare { get; set; } = 0.8;

    /// <summary>Share that writes may use (default 0.95 = 1140); the rest stays free for other tools on the same token.</summary>
    public double WriteShare { get; set; } = 0.95;

    /// <summary>
    /// Longest delay before a request (default five minutes = one window). A request that would have to wait longer fails with
    /// <see cref="CloudflareRateBudgetExceededException"/> before anything is sent.
    /// </summary>
    public TimeSpan MaxDelay { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Label of the budget in metrics and events (for example the tenant name). Without it a short keyed hash of the token is used, never the token.</summary>
    public string? Name { get; set; }

    /// <exception cref="CloudflareConfigurationException">A setting is out of range.</exception>
    public void Validate()
    {
        if (RequestsPerWindow is < 1 or > 1_000_000) throw new CloudflareConfigurationException("Cloudflare: RateBudget.RequestsPerWindow must be 1 to 1000000.");
        if (Window <= TimeSpan.Zero || Window > TimeSpan.FromHours(24)) throw new CloudflareConfigurationException("Cloudflare: RateBudget.Window must be positive and at most 24 hours.");
        if (ReadShare is <= 0 or > 1 || double.IsNaN(ReadShare)) throw new CloudflareConfigurationException("Cloudflare: RateBudget.ReadShare must be greater than 0 and at most 1.");
        if (WriteShare is <= 0 or > 1 || double.IsNaN(WriteShare)) throw new CloudflareConfigurationException("Cloudflare: RateBudget.WriteShare must be greater than 0 and at most 1.");
        if (MaxDelay < TimeSpan.Zero) throw new CloudflareConfigurationException("Cloudflare: RateBudget.MaxDelay must not be negative.");
        if (Name is { Length: > 64 }) throw new CloudflareConfigurationException("Cloudflare: RateBudget.Name must have at most 64 characters.");
    }

    internal CloudflareRateBudgetOptions Copy() => (CloudflareRateBudgetOptions)MemberwiseClone();
}

/// <summary>Kind of a request for the budget: reads and writes have their own share (<see cref="CloudflareRateBudgetOptions.ReadShare"/>, <see cref="CloudflareRateBudgetOptions.WriteShare"/>).</summary>
public enum CloudflareRequestKind
{
    Read,
    Write,
}

/// <summary>What the budget did (event <see cref="CloudflareRateBudget.Delayed"/>/<see cref="CloudflareRateBudget.Throttled"/>). Carries the budget label, never the token.</summary>
public sealed record CloudflareRateBudgetEvent(string Budget, CloudflareRequestKind Kind, TimeSpan Delay, int UsedInWindow, int Limit, string Reason);

/// <summary>State of a budget at one moment.</summary>
public sealed record CloudflareRateBudgetSnapshot(string Budget, int UsedInWindow, int ReadLimit, int WriteLimit, int Limit, DateTimeOffset? BlockedUntil, long Delays, long Requests);

/// <summary>A request would have to wait longer than <see cref="CloudflareRateBudgetOptions.MaxDelay"/>; nothing was sent.</summary>
public sealed class CloudflareRateBudgetExceededException(string budget, TimeSpan wait)
    : InvalidOperationException($"Cloudflare: the request budget \"{budget}\" is used up; the next slot is in {wait.TotalSeconds:0} s (more than RateBudget.MaxDelay). Nothing was sent.")
{
    public string Budget { get; } = budget;
    public TimeSpan Wait { get; } = wait;
}

/// <summary>
/// Sliding-window counter of one API token (0.9.0). Every client that uses the token shares the one instance (see
/// <see cref="CloudflareRateBudgetRegistry"/>). <see cref="AcquireAsync"/> takes a slot or waits until one is free; it never throws for a full budget unless the
/// wait would exceed <see cref="CloudflareRateBudgetOptions.MaxDelay"/>. A 429 from Cloudflare (<see cref="ReportThrottled"/>) blocks every request of the
/// token until the answer's <c>Retry-After</c> has passed. Thread-safe.
/// </summary>
public sealed class CloudflareRateBudget
{
    internal static readonly Meter Meter = new("InfinitySuite360.Cloudflare", "0.9.0");
    private static readonly Counter<long> RequestCounter = Meter.CreateCounter<long>("cloudflare.budget.requests", description: "Requests counted against a Cloudflare token budget.");
    private static readonly Counter<long> DelayCounter = Meter.CreateCounter<long>("cloudflare.budget.delays", description: "Requests delayed by a Cloudflare token budget.");
    private static readonly Histogram<double> DelayHistogram = Meter.CreateHistogram<double>("cloudflare.budget.delay", "ms", "Delay before a request because the budget was used up.");

    private readonly object _gate = new();
    private readonly List<DateTimeOffset> _sent = [];
    private readonly CloudflareRateBudgetOptions _options;
    private readonly TimeProvider _time;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private DateTimeOffset? _blockedUntil;
    private long _delays;
    private long _requests;

    /// <param name="options">Settings (copied).</param>
    /// <param name="name">Label for metrics and events; never pass the token.</param>
    /// <param name="time">Clock (tests pass a fake clock).</param>
    /// <param name="delay">How to wait (tests advance the fake clock instead of sleeping).</param>
    public CloudflareRateBudget(CloudflareRateBudgetOptions options, string name, TimeProvider? time = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options.Copy();
        Name = string.IsNullOrWhiteSpace(name) ? "cloudflare" : name;
        _time = time ?? TimeProvider.System;
        _delay = delay ?? ((t, ct) => Task.Delay(t, _time, ct));
    }

    /// <summary>Label of the budget (tenant name or keyed hash; never the token).</summary>
    public string Name { get; }

    /// <summary>Limit for reads in one window.</summary>
    public int ReadLimit => Math.Max(1, (int)Math.Floor(_options.RequestsPerWindow * _options.ReadShare));

    /// <summary>Limit for writes in one window.</summary>
    public int WriteLimit => Math.Max(1, (int)Math.Floor(_options.RequestsPerWindow * _options.WriteShare));

    /// <summary>A request had to wait (raised before the wait).</summary>
    public event Action<CloudflareRateBudgetEvent>? Delayed;

    /// <summary>Cloudflare answered 429; the budget blocks the token until the <c>Retry-After</c> has passed.</summary>
    public event Action<CloudflareRateBudgetEvent>? Throttled;

    /// <summary>Takes a slot for one request of <paramref name="kind"/>, waiting first when the share for that kind is used up.</summary>
    /// <exception cref="CloudflareRateBudgetExceededException">The wait would be longer than <see cref="CloudflareRateBudgetOptions.MaxDelay"/>.</exception>
    public async Task AcquireAsync(CloudflareRequestKind kind, CancellationToken ct = default)
    {
        var limit = kind == CloudflareRequestKind.Write ? WriteLimit : ReadLimit;
        for (var round = 0; ; round++)
        {
            ct.ThrowIfCancellationRequested();
            TimeSpan wait;
            int used;
            string reason;
            lock (_gate)
            {
                var now = _time.GetUtcNow();
                Prune(now);
                used = _sent.Count;
                if (_blockedUntil is { } until && until > now)
                {
                    wait = until - now;
                    reason = "Cloudflare answered 429 (Retry-After)";
                }
                else if (used < limit)
                {
                    _sent.Add(now);
                    _requests++;
                    RequestCounter.Add(1, Tags(kind));
                    return;
                }
                else
                {
                    // The (used - limit)-th oldest request has to leave the window before a slot is free for this kind.
                    wait = _sent[used - limit] + _options.Window - now;
                    reason = $"{used} of {limit} {(kind == CloudflareRequestKind.Write ? "write" : "read")} slots used in the window";
                }
                if (wait <= TimeSpan.Zero) continue;
                if (wait > _options.MaxDelay) throw new CloudflareRateBudgetExceededException(Name, wait);
                _delays++;
            }
            DelayCounter.Add(1, Tags(kind));
            DelayHistogram.Record(wait.TotalMilliseconds, Tags(kind));
            Delayed?.Invoke(new CloudflareRateBudgetEvent(Name, kind, wait, used, limit, reason));
            await _delay(wait, ct).ConfigureAwait(false);
            if (round > 10_000) throw new CloudflareRateBudgetExceededException(Name, wait);
        }
    }

    /// <summary>Cloudflare answered 429: block every request of this token until <paramref name="retryAfter"/> (default one minute, at most one window) has passed.</summary>
    public void ReportThrottled(TimeSpan? retryAfter, CloudflareRequestKind kind = CloudflareRequestKind.Read)
    {
        var wait = retryAfter is { } r && r > TimeSpan.Zero ? r : TimeSpan.FromMinutes(1);
        if (wait > _options.Window) wait = _options.Window;
        int used;
        lock (_gate)
        {
            var until = _time.GetUtcNow() + wait;
            if (_blockedUntil is null || until > _blockedUntil) _blockedUntil = until;
            used = _sent.Count;
        }
        Throttled?.Invoke(new CloudflareRateBudgetEvent(Name, kind, wait, used, _options.RequestsPerWindow, "Cloudflare answered 429"));
    }

    /// <summary>Current state (requests in the window, limits, block).</summary>
    public CloudflareRateBudgetSnapshot Snapshot()
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            Prune(now);
            return new CloudflareRateBudgetSnapshot(Name, _sent.Count, ReadLimit, WriteLimit, _options.RequestsPerWindow,
                _blockedUntil is { } u && u > now ? u : null, _delays, _requests);
        }
    }

    public override string ToString() => $"CloudflareRateBudget({Name})";

    private void Prune(DateTimeOffset now)
    {
        var cutoff = now - _options.Window;
        var drop = 0;
        while (drop < _sent.Count && _sent[drop] <= cutoff) drop++;
        if (drop > 0) _sent.RemoveRange(0, drop);
        if (_blockedUntil is { } u && u <= now) _blockedUntil = null;
    }

    private KeyValuePair<string, object?>[] Tags(CloudflareRequestKind kind) =>
        [new("budget", Name), new("kind", kind == CloudflareRequestKind.Write ? "write" : "read")];
}

/// <summary>
/// The budgets of one process (0.9.0): one <see cref="CloudflareRateBudget"/> per API token and base address, shared by every client that uses the token.
/// The key is a keyed hash (HMAC-SHA-256 with a random key per registry) of the token: the token itself is not stored, and the hash cannot be compared with
/// anything outside the process. Registered as a singleton by the dependency injection registration; <see cref="CloudflareClientFactory"/> creates its own
/// when none is passed.
/// </summary>
public sealed class CloudflareRateBudgetRegistry
{
    private readonly ConcurrentDictionary<string, CloudflareRateBudget> _budgets = new(StringComparer.Ordinal);
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly TimeProvider? _time;
    private readonly Func<TimeSpan, CancellationToken, Task>? _delay;

    public CloudflareRateBudgetRegistry(TimeProvider? time = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _time = time;
        _delay = delay;
    }

    /// <summary>Number of budgets (distinct tokens) in use.</summary>
    public int Count => _budgets.Count;

    /// <summary>
    /// The shared budget for the token of <paramref name="options"/>, or null when <see cref="CloudflareRateBudgetOptions.Enabled"/> is off or no token is
    /// set. The settings of the first caller for a token win; later callers with other settings share the same budget.
    /// </summary>
    public CloudflareRateBudget? For(CloudflareOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.RateBudget.Enabled || string.IsNullOrEmpty(options.ApiToken)) return null;
        var fingerprint = Fingerprint(options.ApiToken);
        var key = fingerprint + "|" + options.BaseAddress.TrimEnd('/').ToLowerInvariant();
        return _budgets.GetOrAdd(key, _ => new CloudflareRateBudget(options.RateBudget, options.RateBudget.Name ?? "token-" + fingerprint[..8], _time, _delay));
    }

    /// <summary>Every budget (for a status page: labels and counters, no token).</summary>
    public IReadOnlyList<CloudflareRateBudgetSnapshot> Snapshots() => _budgets.Values.Select(b => b.Snapshot()).OrderBy(s => s.Budget, StringComparer.Ordinal).ToList();

    /// <summary>Keyed hash of a token (hex). Equal tokens give equal values within this registry only.</summary>
    internal string Fingerprint(string token) => Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    public override string ToString() => $"CloudflareRateBudgetRegistry({Count} budgets)";
}

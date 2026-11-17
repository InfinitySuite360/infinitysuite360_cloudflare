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

    /// <summary>
    /// Share of <see cref="RequestsPerWindow"/> that reads may use (default 0.8 = 960): watchers and dashboards never eat the headroom of a write. Reads
    /// that a write method makes to prepare its change (for example the member list before a removal, the current state before an upsert) count as
    /// writes (0.9.1), so a busy dashboard cannot hold up a change.
    /// </summary>
    public double ReadShare { get; set; } = 0.8;

    /// <summary>Share that writes may use (default 0.95 = 1140); the rest stays free for other tools on the same token.</summary>
    public double WriteShare { get; set; } = 0.95;

    /// <summary>
    /// Longest wait of one call before its request is sent (default five minutes = one window), counted from the call on (0.9.1: per call, across every
    /// re-check). A call whose slot is further away fails with <see cref="CloudflareRateBudgetExceededException"/> before anything is sent.
    /// <see cref="HttpClient.Timeout"/> does not cover this wait: it only starts with the request.
    /// </summary>
    public TimeSpan MaxDelay { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Most calls that may wait at the same time (default 1000, 0.9.1). One call more fails at once with
    /// <see cref="CloudflareRateBudgetExceededException"/> (<see cref="CloudflareRateBudgetExceededException.QueueFull"/>) instead of piling up tasks.
    /// </summary>
    public int MaxQueued { get; set; } = 1000;

    /// <summary>Label of the budget in metrics and events (for example the tenant name). Without it a short keyed hash of the token is used, never the token.</summary>
    public string? Name { get; set; }

    /// <exception cref="CloudflareConfigurationException">A setting is out of range.</exception>
    public void Validate()
    {
        if (RequestsPerWindow is < 1 or > 1_000_000) throw new CloudflareConfigurationException("Cloudflare: RateBudget.RequestsPerWindow must be 1 to 1000000.");
        if (Window <= TimeSpan.Zero || Window > TimeSpan.FromHours(24)) throw new CloudflareConfigurationException("Cloudflare: RateBudget.Window must be positive and at most 24 hours.");
        if (ReadShare is <= 0 or > 1 || double.IsNaN(ReadShare)) throw new CloudflareConfigurationException("Cloudflare: RateBudget.ReadShare must be greater than 0 and at most 1.");
        if (WriteShare is <= 0 or > 1 || double.IsNaN(WriteShare)) throw new CloudflareConfigurationException("Cloudflare: RateBudget.WriteShare must be greater than 0 and at most 1.");
        if (MaxDelay < TimeSpan.Zero || MaxDelay > TimeSpan.FromHours(24)) throw new CloudflareConfigurationException("Cloudflare: RateBudget.MaxDelay must be 0 to 24 hours.");
        if (MaxQueued is < 0 or > 1_000_000) throw new CloudflareConfigurationException("Cloudflare: RateBudget.MaxQueued must be 0 to 1000000.");
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

/// <summary>
/// State of a budget at one moment. <see cref="BlockedUntil"/> is wall-clock time for display only; the budget itself measures with the monotonic clock
/// (0.9.1), so a change of the system clock neither frees nor blocks slots.
/// </summary>
public sealed record CloudflareRateBudgetSnapshot(string Budget, int UsedInWindow, int ReadLimit, int WriteLimit, int Limit, DateTimeOffset? BlockedUntil, long Delays, long Requests)
{
    /// <summary>Calls waiting for a slot at this moment (0.9.1).</summary>
    public int Queued { get; init; }
}

/// <summary>A request would have to wait longer than <see cref="CloudflareRateBudgetOptions.MaxDelay"/>, or too many calls wait already; nothing was sent.</summary>
public sealed class CloudflareRateBudgetExceededException : InvalidOperationException
{
    public CloudflareRateBudgetExceededException(string budget, TimeSpan wait)
        : this(budget, wait, false) { }

    internal CloudflareRateBudgetExceededException(string budget, TimeSpan wait, bool queueFull)
        : base(queueFull
            ? $"Cloudflare: the request budget \"{budget}\" has too many waiting calls (RateBudget.MaxQueued). Nothing was sent."
            : $"Cloudflare: the request budget \"{budget}\" is used up; the next slot is in {wait.TotalSeconds:0} s (more than RateBudget.MaxDelay). Nothing was sent.")
    {
        Budget = budget;
        Wait = wait;
        QueueFull = queueFull;
    }

    public string Budget { get; }
    public TimeSpan Wait { get; }

    /// <summary>True when the call was refused because <see cref="CloudflareRateBudgetOptions.MaxQueued"/> calls were waiting already (0.9.1).</summary>
    public bool QueueFull { get; }
}

/// <summary>
/// Sliding-window counter of one API token (0.9.0, reworked in 0.9.1). Every client that uses the token shares the one instance (see
/// <see cref="CloudflareRateBudgetRegistry"/>). <see cref="AcquireAsync"/> takes a slot or waits until one is free:
/// <list type="bullet">
/// <item>waiting calls of one kind are served first come, first served (a queue per kind, so a waiting read never holds up a write);</item>
/// <item>the wait of one call is bounded by <see cref="CloudflareRateBudgetOptions.MaxDelay"/> from the start of the call, and at most
/// <see cref="CloudflareRateBudgetOptions.MaxQueued"/> calls wait; beyond either the call fails before anything is sent;</item>
/// <item>time is measured with the monotonic clock (<see cref="TimeProvider.GetTimestamp"/>), never with the wall clock;</item>
/// <item><see cref="Delayed"/> is raised once per waiting call; a failing subscriber never breaks a request.</item>
/// </list>
/// A 429 from Cloudflare (<see cref="ReportThrottled"/>) blocks every request of the token until the answer's <c>Retry-After</c> has passed. Thread-safe.
/// </summary>
public sealed class CloudflareRateBudget
{
    internal static readonly Meter Meter = new("InfinitySuite360.Cloudflare", "0.9.1");
    private static readonly Counter<long> RequestCounter = Meter.CreateCounter<long>("cloudflare.budget.requests", description: "Requests counted against a Cloudflare token budget.");
    private static readonly Counter<long> DelayCounter = Meter.CreateCounter<long>("cloudflare.budget.delays", description: "Requests delayed by a Cloudflare token budget.");
    private static readonly Counter<long> RefusedCounter = Meter.CreateCounter<long>("cloudflare.budget.refused", description: "Requests refused by a Cloudflare token budget (wait too long or queue full).");
    private static readonly Counter<long> SubscriberErrorCounter = Meter.CreateCounter<long>("cloudflare.budget.subscriber_errors", description: "Exceptions thrown by subscribers of budget events (swallowed).");
    private static readonly Histogram<double> DelayHistogram = Meter.CreateHistogram<double>("cloudflare.budget.delay", "ms", "Delay before a request because the budget was used up.");

    /// <summary>Most distinct budget labels in metrics per process (0.9.1); further budgets are reported as <c>other</c>.</summary>
    public const int MaxMetricLabels = 100;

    private static readonly ConcurrentDictionary<string, byte> Labels = new(StringComparer.Ordinal);

    private readonly object _gate = new();
    private readonly List<long> _sent = [];
    private readonly LinkedList<CloudflareRequestKind>[] _queues = [new(), new()];
    private readonly CloudflareRateBudgetOptions _options;
    private readonly TimeProvider _time;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private readonly string _label;
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _blockedSince;
    private TimeSpan _blockedFor;
    private long _lastUsed;
    private long _delays;
    private long _requests;

    // Registry membership (0.9.1, L-5): an idle budget can be removed from its registry; a client that still holds it is forwarded to the current one.
    internal CloudflareRateBudgetRegistry? Registry;
    internal string? RegistryKey;
    private bool _retired;

    /// <param name="options">Settings (copied).</param>
    /// <param name="name">Label for metrics and events; never pass the token.</param>
    /// <param name="time">Clock (tests pass a fake clock). The budget uses its monotonic timestamps; the wall clock only for <see cref="Snapshot"/>.</param>
    /// <param name="delay">How to wait (tests advance the fake clock instead of sleeping).</param>
    public CloudflareRateBudget(CloudflareRateBudgetOptions options, string name, TimeProvider? time = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options.Copy();
        Name = string.IsNullOrWhiteSpace(name) ? "cloudflare" : name;
        _time = time ?? TimeProvider.System;
        _delay = delay ?? ((t, ct) => Task.Delay(t, _time, ct));
        _label = Label(Name);
        _lastUsed = _time.GetTimestamp();
    }

    /// <summary>Label of the budget (tenant name or keyed hash; never the token).</summary>
    public string Name { get; }

    /// <summary>Limit for reads in one window.</summary>
    public int ReadLimit => Math.Max(1, (int)Math.Floor(_options.RequestsPerWindow * _options.ReadShare));

    /// <summary>Limit for writes in one window.</summary>
    public int WriteLimit => Math.Max(1, (int)Math.Floor(_options.RequestsPerWindow * _options.WriteShare));

    /// <summary>The clock of the budget (also used to read a <c>Retry-After</c> date).</summary>
    internal TimeProvider Time => _time;

    /// <summary>A request had to wait (raised once per call, before the wait). Exceptions of subscribers are swallowed.</summary>
    public event Action<CloudflareRateBudgetEvent>? Delayed;

    /// <summary>Cloudflare answered 429; the budget blocks the token until the <c>Retry-After</c> has passed. Exceptions of subscribers are swallowed.</summary>
    public event Action<CloudflareRateBudgetEvent>? Throttled;

    /// <summary>Takes a slot for one request of <paramref name="kind"/>, waiting first (in order of arrival) when the share for that kind is used up.</summary>
    /// <exception cref="CloudflareRateBudgetExceededException">The wait would end later than <see cref="CloudflareRateBudgetOptions.MaxDelay"/> after the call,
    /// or <see cref="CloudflareRateBudgetOptions.MaxQueued"/> calls wait already.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="ct"/> was cancelled while waiting; the place in the queue is given up.</exception>
    public Task AcquireAsync(CloudflareRequestKind kind, CancellationToken ct = default) => Current().AcquireCoreAsync(kind, ct);

    private async Task AcquireCoreAsync(CloudflareRequestKind kind, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var start = _time.GetTimestamp();
        var limit = kind == CloudflareRequestKind.Write ? WriteLimit : ReadLimit;
        var queue = _queues[(int)kind];
        LinkedListNode<CloudflareRequestKind>? ticket;
        TimeSpan wait;
        int used;
        string reason;
        var forward = false;
        lock (_gate)
        {
            if (_retired)
            {
                forward = true;
                ticket = null;
                wait = TimeSpan.Zero;
                used = 0;
                reason = "";
            }
            else
            {
                var now = _time.GetTimestamp();
                Prune(now);
                _lastUsed = now;
                if (queue.Count == 0 && TryTake(now, kind, limit)) return;
                if (QueuedLocked() >= _options.MaxQueued)
                {
                    Refused(kind);
                    throw new CloudflareRateBudgetExceededException(Name, TimeSpan.Zero, queueFull: true);
                }
                wait = Estimate(now, limit, queue.Count, out used, out reason, kind);
                if (wait > _options.MaxDelay)
                {
                    Refused(kind);
                    throw new CloudflareRateBudgetExceededException(Name, wait);
                }
                ticket = queue.AddLast(kind);
                _delays++;
            }
        }
        if (forward)
        {
            await Current().AcquireCoreAsync(kind, ct).ConfigureAwait(false);
            return;
        }

        DelayCounter.Add(1, Tags(kind));
        DelayHistogram.Record(wait.TotalMilliseconds, Tags(kind));
        Raise(Delayed, new CloudflareRateBudgetEvent(Name, kind, wait, used, limit, reason));
        try
        {
            while (true)
            {
                Task changed;
                TimeSpan sleep;
                lock (_gate)
                {
                    var now = _time.GetTimestamp();
                    Prune(now);
                    _lastUsed = now;
                    if (queue.First == ticket && TryTake(now, kind, limit))
                    {
                        queue.Remove(ticket!);
                        ticket = null;
                        Signal();
                        return;
                    }
                    var remaining = _options.MaxDelay - _time.GetElapsedTime(start, now);
                    wait = Estimate(now, limit, Position(queue, ticket!), out _, out _, kind);
                    if (wait > remaining)
                    {
                        Refused(kind);
                        throw new CloudflareRateBudgetExceededException(Name, wait);
                    }
                    // A call whose slot is free but which is not first waits for the calls before it (signalled), at most until its deadline.
                    sleep = wait > TimeSpan.Zero ? wait : remaining;
                    changed = _changed.Task;
                }
                await WaitAsync(sleep, changed, ct).ConfigureAwait(false);
            }
        }
        finally
        {
            if (ticket is not null)
                lock (_gate)
                {
                    if (ticket.List is not null)
                    {
                        queue.Remove(ticket);
                        Signal();
                    }
                }
        }
    }

    private async Task WaitAsync(TimeSpan sleep, Task changed, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var delay = _delay(sleep, cts.Token);
        var first = await Task.WhenAny(delay, changed).ConfigureAwait(false);
        if (first != delay) cts.Cancel();
        try { await delay.ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* our own cancel after a signal */ }
        ct.ThrowIfCancellationRequested();
    }

    /// <summary>Cloudflare answered 429: block every request of this token until <paramref name="retryAfter"/> (default one minute, at most one window) has passed.</summary>
    public void ReportThrottled(TimeSpan? retryAfter, CloudflareRequestKind kind = CloudflareRequestKind.Read)
    {
        var target = Current();
        if (!ReferenceEquals(target, this))
        {
            target.ReportThrottled(retryAfter, kind);
            return;
        }
        var wait = retryAfter is { } r && r > TimeSpan.Zero ? r : TimeSpan.FromMinutes(1);
        if (wait > _options.Window) wait = _options.Window;
        int used;
        lock (_gate)
        {
            var now = _time.GetTimestamp();
            _lastUsed = now;
            if (wait > BlockedRemaining(now))
            {
                _blockedSince = now;
                _blockedFor = wait;
            }
            used = _sent.Count;
            Signal();
        }
        Raise(Throttled, new CloudflareRateBudgetEvent(Name, kind, wait, used, _options.RequestsPerWindow, "Cloudflare answered 429"));
    }

    /// <summary>Current state (requests in the window, limits, block, waiting calls).</summary>
    public CloudflareRateBudgetSnapshot Snapshot()
    {
        lock (_gate)
        {
            var now = _time.GetTimestamp();
            Prune(now);
            var blocked = BlockedRemaining(now);
            return new CloudflareRateBudgetSnapshot(Name, _sent.Count, ReadLimit, WriteLimit, _options.RequestsPerWindow,
                blocked > TimeSpan.Zero ? _time.GetUtcNow() + blocked : null, _delays, _requests) { Queued = QueuedLocked() };
        }
    }

    public override string ToString() => $"CloudflareRateBudget({Name})";

    // ------------------------------------------------------------------ registry support (L-5)

    /// <summary>This budget, or the one of the registry that replaced it after it was removed as idle.</summary>
    private CloudflareRateBudget Current()
    {
        var budget = this;
        for (var i = 0; i < 8 && budget.IsRetired(); i++)
            budget = budget.Registry is { } registry && budget.RegistryKey is { } key ? registry.Readmit(key, budget) : budget;
        return budget;
    }

    private bool IsRetired()
    {
        lock (_gate) return _retired;
    }

    /// <summary>Retires the budget when nothing in it counts any more (no request in the window, no block, nobody waiting). Called by the registry under its rules.</summary>
    internal bool TryRetire(Func<bool> remove)
    {
        lock (_gate)
        {
            var now = _time.GetTimestamp();
            Prune(now);
            if (_retired || _sent.Count > 0 || BlockedRemaining(now) > TimeSpan.Zero || QueuedLocked() > 0) return false;
            if (!remove()) return false;
            _retired = true;
            return true;
        }
    }

    /// <summary>Makes a retired budget current again (under its lock, so that a concurrent retire cannot interleave).</summary>
    internal CloudflareRateBudget Readmit(Func<CloudflareRateBudget> getOrAdd)
    {
        lock (_gate)
        {
            var current = getOrAdd();
            if (ReferenceEquals(current, this)) _retired = false;
            return current;
        }
    }

    /// <summary>Monotonic timestamp of the last use (for the registry's least-recently-used order).</summary>
    internal long LastUsed
    {
        get { lock (_gate) return _lastUsed; }
    }

    // ------------------------------------------------------------------ internals (callers hold _gate)

    private bool TryTake(long now, CloudflareRequestKind kind, int limit)
    {
        if (BlockedRemaining(now) > TimeSpan.Zero || _sent.Count >= limit) return false;
        _sent.Add(now);
        _requests++;
        RequestCounter.Add(1, Tags(kind));
        return true;
    }

    /// <summary>
    /// Earliest moment the call at <paramref name="position"/> of its queue can get a slot: the (used - limit + position)-th oldest request has to leave
    /// the window; slots that calls before it have not taken yet leave at the earliest one window from now; a block by 429 comes on top.
    /// </summary>
    private TimeSpan Estimate(long now, int limit, int position, out int used, out string reason, CloudflareRequestKind kind)
    {
        used = _sent.Count;
        var blocked = BlockedRemaining(now);
        var k = used - limit + position;
        var slot = k < 0 ? TimeSpan.Zero : k < used ? _options.Window - _time.GetElapsedTime(_sent[k], now) : _options.Window;
        if (slot < TimeSpan.Zero) slot = TimeSpan.Zero;
        reason = blocked >= slot && blocked > TimeSpan.Zero
            ? "Cloudflare answered 429 (Retry-After)"
            : $"{used} of {limit} {(kind == CloudflareRequestKind.Write ? "write" : "read")} slots used in the window, {position} call(s) waiting before";
        return blocked > slot ? blocked : slot;
    }

    private static int Position(LinkedList<CloudflareRequestKind> queue, LinkedListNode<CloudflareRequestKind> ticket)
    {
        var i = 0;
        for (var n = queue.First; n is not null && n != ticket; n = n.Next) i++;
        return i;
    }

    private int QueuedLocked() => _queues[0].Count + _queues[1].Count;

    private TimeSpan BlockedRemaining(long now)
    {
        if (_blockedFor <= TimeSpan.Zero) return TimeSpan.Zero;
        var left = _blockedFor - _time.GetElapsedTime(_blockedSince, now);
        if (left > TimeSpan.Zero) return left;
        _blockedFor = TimeSpan.Zero;
        return TimeSpan.Zero;
    }

    private void Prune(long now)
    {
        var drop = 0;
        while (drop < _sent.Count && _time.GetElapsedTime(_sent[drop], now) >= _options.Window) drop++;
        if (drop > 0) _sent.RemoveRange(0, drop);
    }

    private void Signal()
    {
        var old = _changed;
        _changed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        old.TrySetResult();
    }

    private void Refused(CloudflareRequestKind kind) => RefusedCounter.Add(1, Tags(kind));

    private void Raise(Action<CloudflareRateBudgetEvent>? handlers, CloudflareRateBudgetEvent e)
    {
        if (handlers is null) return;
        foreach (var handler in handlers.GetInvocationList())
        {
            try { ((Action<CloudflareRateBudgetEvent>)handler)(e); }
            catch (Exception)
            {
                // A subscriber (logging, Slack, metrics) must never break a request or leave a response undisposed (L-3, 0.9.1).
                SubscriberErrorCounter.Add(1, new KeyValuePair<string, object?>("budget", _label));
            }
        }
    }

    private KeyValuePair<string, object?>[] Tags(CloudflareRequestKind kind) =>
        [new("budget", _label), new("kind", kind == CloudflareRequestKind.Write ? "write" : "read")];

    /// <summary>The metric label of a budget name: the name for the first <see cref="MaxMetricLabels"/> names of the process, <c>other</c> after that.</summary>
    internal static string Label(string name)
    {
        if (Labels.ContainsKey(name)) return name;
        if (Labels.Count >= MaxMetricLabels) return "other";
        Labels.TryAdd(name, 0);
        return name;
    }
}

/// <summary>
/// The budgets of one process (0.9.0): one <see cref="CloudflareRateBudget"/> per API token and base address, shared by every client that uses the token.
/// The key is a keyed hash (HMAC-SHA-256 with a random key per registry) of the token: the token itself is not stored, and the hash cannot be compared with
/// anything outside the process. Registered as a singleton by the dependency injection registration; <see cref="CloudflareClientFactory"/> creates its own
/// when none is passed. At most <see cref="MaxBudgets"/> budgets are kept (0.9.1): beyond that, idle budgets (no request in the window, no block, nobody
/// waiting) are removed, least recently used first; a client that still holds a removed budget is moved to the current one on its next request.
/// </summary>
public sealed class CloudflareRateBudgetRegistry
{
    private readonly ConcurrentDictionary<string, CloudflareRateBudget> _budgets = new(StringComparer.Ordinal);
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly TimeProvider? _time;
    private readonly Func<TimeSpan, CancellationToken, Task>? _delay;
    private readonly object _trim = new();

    public CloudflareRateBudgetRegistry(TimeProvider? time = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _time = time;
        _delay = delay;
    }

    /// <summary>Most budgets kept before idle ones are removed (default 1024, 0.9.1). Busy budgets are never removed.</summary>
    public int MaxBudgets { get; init; } = 1024;

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
        var budget = _budgets.GetOrAdd(key, k => Create(k, options, fingerprint));
        if (_budgets.Count > MaxBudgets) Trim(budget);
        return budget;
    }

    /// <summary>Every budget (for a status page: labels and counters, no token).</summary>
    public IReadOnlyList<CloudflareRateBudgetSnapshot> Snapshots() => _budgets.Values.Select(b => b.Snapshot()).OrderBy(s => s.Budget, StringComparer.Ordinal).ToList();

    /// <summary>Keyed hash of a token (hex). Equal tokens give equal values within this registry only.</summary>
    internal string Fingerprint(string token) => Convert.ToHexString(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    public override string ToString() => $"CloudflareRateBudgetRegistry({Count} budgets)";

    private CloudflareRateBudget Create(string key, CloudflareOptions options, string fingerprint) =>
        new(options.RateBudget, options.RateBudget.Name ?? "token-" + fingerprint[..8], _time, _delay) { Registry = this, RegistryKey = key };

    /// <summary>The current budget for <paramref name="key"/>: the retired one again when no other took its place.</summary>
    internal CloudflareRateBudget Readmit(string key, CloudflareRateBudget retired) =>
        retired.Readmit(() => _budgets.GetOrAdd(key, retired));

    private void Trim(CloudflareRateBudget keep)
    {
        lock (_trim)
        {
            var excess = _budgets.Count - MaxBudgets;
            if (excess <= 0) return;
            foreach (var (key, budget) in _budgets.ToArray().OrderBy(kv => kv.Value.LastUsed))
            {
                if (excess <= 0) break;
                if (ReferenceEquals(budget, keep)) continue;
                if (budget.TryRetire(() => _budgets.TryRemove(new KeyValuePair<string, CloudflareRateBudget>(key, budget)))) excess--;
            }
        }
    }
}

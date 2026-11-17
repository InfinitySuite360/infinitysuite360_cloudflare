using System.Collections;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using InfinitySuite360.Cloudflare.AccessJwt;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;
using InfinitySuite360.Cloudflare.Tests.Coverage;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>
/// Delays that complete when the test moves the clock (several waiting calls at once). Each delay honours its cancellation token.
/// </summary>
internal sealed class ManualDelays(FakeClock clock)
{
    private readonly List<(TimeSpan Due, TaskCompletionSource Done)> _pending = [];
    private TimeSpan _elapsed;

    public int Pending { get { lock (_pending) return _pending.Count(p => !p.Done.Task.IsCompleted); } }

    public Task Delay(TimeSpan wait, CancellationToken ct)
    {
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_pending) _pending.Add((_elapsed + wait, done));
        ct.Register(() => done.TrySetCanceled(ct));
        return done.Task;
    }

    public void Advance(TimeSpan by)
    {
        List<TaskCompletionSource> due;
        lock (_pending)
        {
            _elapsed += by;
            clock.Advance(by);
            due = _pending.Where(p => p.Due <= _elapsed).Select(p => p.Done).ToList();
            _pending.RemoveAll(p => p.Due <= _elapsed);
        }
        foreach (var d in due) d.TrySetResult();
    }
}

/// <summary>
/// 0.9.1: the findings of the independent review of P6 (H-1, M-1 … M-3, L-1 … L-8). Fake handler, fake clock, synthetic tokens; no network, no real
/// Cloudflare call.
/// </summary>
public class P6HardeningTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 17, 8, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Settle = TimeSpan.FromSeconds(10);

    private static CloudflareRateBudget Budget(FakeClock clock, Func<TimeSpan, CancellationToken, Task> delay, Action<CloudflareRateBudgetOptions>? configure = null)
    {
        var o = new CloudflareRateBudgetOptions { RequestsPerWindow = 1, Window = TimeSpan.FromMinutes(5), ReadShare = 1.0, WriteShare = 1.0, MaxDelay = TimeSpan.FromHours(1) };
        configure?.Invoke(o);
        return new CloudflareRateBudget(o, "tenant-h", clock, delay);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var sw = Stopwatch.StartNew();
        while (!condition())
        {
            if (sw.Elapsed > Settle) throw new TimeoutException("condition not reached");
            await Task.Delay(5);
        }
    }

    // ================================================================== H-1: last super administrator

    private const string Paging = """{"page":1,"per_page":50,"total_pages":1}""";

    private static (CloudflareClient Client, FakeHandler Handler) Members(string membersJson)
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        h.Responder = (r, _) => r.Method == HttpMethod.Get ? FakeHandler.Ok(membersJson, Paging) : FakeHandler.Ok("""{"id":"x"}""");
        return (cf, h);
    }

    [Fact]
    public async Task H1_a_super_administrator_by_policy_permission_group_is_protected()
    {
        var (cf, h) = Members("""
            [{"id":"m1","status":"accepted","roles":[],"policies":[{"id":"p1","access":"allow","permission_groups":[{"id":"g1","name":"Super Administrator – All Privileges"}],"resource_groups":[{"id":"rg1","name":"account"}]}]},
             {"id":"m2","status":"accepted","policies":[{"id":"p2","access":"allow","permission_groups":[{"id":"g2","name":"Administrator"}]}]}]
            """);
        await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Members.RemoveAsync("m1", allowRemoval: true));
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);
        Assert.True(await cf.Members.RemoveAsync("m2", allowRemoval: true));
        var member = Assert.Single(await cf.Members.ListAsync(), m => m.Id == "m1");
        Assert.Equal("Super Administrator – All Privileges", Assert.Single(Assert.Single(member.Policies).PermissionGroups).Name);
    }

    [Fact]
    public async Task H1_pending_and_denied_super_administrators_do_not_count()
    {
        var (cf, h) = Members("""
            [{"id":"m1","status":"accepted","roles":[{"id":"r1","name":"Super Administrator - All Privileges"}]},
             {"id":"m2","status":"pending","roles":[{"id":"r1","name":"Super Administrator - All Privileges"}]},
             {"id":"m3","status":"accepted","policies":[{"access":"deny","permission_groups":[{"name":"Super Administrator - All Privileges"}]}]}]
            """);
        // m2 (invitation not accepted) and m3 (deny policy) cannot step in: m1 is the last one.
        await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Members.RemoveAsync("m1", allowRemoval: true));
        // Removing the pending invitation does not lock anybody out.
        Assert.True(await cf.Members.RemoveAsync("m2", allowRemoval: true));
        Assert.Single(h.Requests, r => r.Method == HttpMethod.Delete);
    }

    [Fact]
    public async Task H1_a_member_without_roles_and_without_policies_is_refused()
    {
        var (cf, h) = Members("""[{"id":"m1","status":"accepted"},{"id":"m2","status":"accepted","roles":[{"name":"Super Administrator - All Privileges"}]}]""");
        var ex = await Assert.ThrowsAsync<CloudflareConflictException>(() => cf.Members.RemoveAsync("m1", allowRemoval: true));
        Assert.Contains("neither roles nor policies", ex.Message);
        Assert.DoesNotContain(h.Requests, r => r.Method == HttpMethod.Delete);
    }

    /// <summary>A handler with a member list that changes with each DELETE and a slow list, so two removals would overlap without the lock.</summary>
    private sealed class MembersAccount : HttpMessageHandler
    {
        private readonly object _gate = new();
        private readonly HashSet<string> _members = ["m1", "m2"];
        public int Deletes;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Method == HttpMethod.Get)
            {
                string[] ids;
                lock (_gate) ids = [.. _members];
                await Task.Delay(50, ct); // the other removal runs meanwhile if nothing serialises them
                var json = "[" + string.Join(",", ids.Select(id => $$"""{"id":"{{id}}","status":"accepted","roles":[{"name":"Super Administrator - All Privileges"}]}""")) + "]";
                return FakeHandler.Ok(json, Paging);
            }
            var removed = request.RequestUri!.AbsolutePath.Split('/')[^1];
            lock (_gate) { _members.Remove(removed); Deletes++; }
            return FakeHandler.Ok("""{"id":"x"}""");
        }
    }

    [Fact]
    public async Task H1_two_parallel_removals_cannot_remove_both_last_super_administrators()
    {
        var account = new MembersAccount();
        var options = new CloudflareOptions { ApiToken = "SYNTHETIC-TOKEN", AccountId = "acc-parallel", AllowWrites = true, RetryBaseDelay = TimeSpan.Zero };
        var a = new CloudflareClient(new CloudflareApiConnection(new HttpClient(account), options, (_, _) => Task.CompletedTask));
        var b = new CloudflareClient(new CloudflareApiConnection(new HttpClient(account), options.Clone(), (_, _) => Task.CompletedTask));
        var results = await Task.WhenAll(Try(() => a.Members.RemoveAsync("m1", allowRemoval: true)), Try(() => b.Members.RemoveAsync("m2", allowRemoval: true)));
        Assert.Equal(1, account.Deletes);
        Assert.Single(results, r => r is true);
        Assert.Single(results, r => r is CloudflareConflictException);

        static async Task<object> Try(Func<Task<bool>> f)
        {
            try { return await f(); }
            catch (Exception ex) { return ex; }
        }
    }

    // ================================================================== M-1: per-call deadline, FIFO, queue limit, one event per call

    [Fact]
    public async Task M1_the_deadline_counts_from_the_call_not_per_round()
    {
        var clock = new FakeClock(T0);
        CloudflareRateBudget? budget = null;
        var waits = new List<TimeSpan>();
        var first = true;
        Task Delay(TimeSpan t, CancellationToken _)
        {
            waits.Add(t);
            clock.Advance(t);
            // While the call waits, Cloudflare answers 429 to another client of the token: the call now has to wait once more.
            if (first) { first = false; budget!.ReportThrottled(TimeSpan.FromSeconds(50)); }
            return Task.CompletedTask;
        }
        budget = Budget(clock, Delay, o => { o.RequestsPerWindow = 1; o.Window = TimeSpan.FromSeconds(40); o.MaxDelay = TimeSpan.FromSeconds(60); });
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        // 40 s for the slot, then 50 s block: 90 s in total, more than MaxDelay 60 s, although every single round is below it.
        var ex = await Assert.ThrowsAsync<CloudflareRateBudgetExceededException>(() => budget.AcquireAsync(CloudflareRequestKind.Read));
        Assert.False(ex.QueueFull);
        Assert.Equal([TimeSpan.FromSeconds(40)], waits);
        Assert.Equal(1, budget.Snapshot().Requests);
        Assert.Equal(0, budget.Snapshot().Queued);
    }

    [Fact]
    public async Task M1_waiting_calls_are_served_first_come_first_served_and_report_once()
    {
        var clock = new FakeClock(T0);
        var delays = new ManualDelays(clock);
        var budget = Budget(clock, delays.Delay);
        var events = new List<CloudflareRateBudgetEvent>();
        budget.Delayed += e => { lock (events) events.Add(e); };
        await budget.AcquireAsync(CloudflareRequestKind.Read);

        var a = budget.AcquireAsync(CloudflareRequestKind.Read);
        var b = budget.AcquireAsync(CloudflareRequestKind.Read);
        var c = budget.AcquireAsync(CloudflareRequestKind.Read);
        Assert.Equal(3, budget.Snapshot().Queued);

        delays.Advance(TimeSpan.FromMinutes(5)); // one slot frees: the first caller gets it, not a later one
        await a.WaitAsync(Settle);
        await WaitUntil(() => budget.Snapshot().Queued == 2 && delays.Pending == 2);
        Assert.False(b.IsCompleted);
        Assert.False(c.IsCompleted);

        delays.Advance(TimeSpan.FromMinutes(5));
        await b.WaitAsync(Settle);
        await WaitUntil(() => delays.Pending == 1);
        Assert.False(c.IsCompleted);

        delays.Advance(TimeSpan.FromMinutes(5));
        await c.WaitAsync(Settle);
        Assert.Equal(3, events.Count); // one event per waiting call, not per round
        Assert.Equal(4, budget.Snapshot().Requests);
    }

    [Fact]
    public async Task M1_a_full_queue_refuses_at_once_and_a_cancelled_call_leaves_the_queue()
    {
        var clock = new FakeClock(T0);
        var delays = new ManualDelays(clock);
        var budget = Budget(clock, delays.Delay, o => o.MaxQueued = 2);
        await budget.AcquireAsync(CloudflareRequestKind.Write);
        using var cancel = new CancellationTokenSource();
        var first = budget.AcquireAsync(CloudflareRequestKind.Write, cancel.Token);
        var second = budget.AcquireAsync(CloudflareRequestKind.Write);
        var full = await Assert.ThrowsAsync<CloudflareRateBudgetExceededException>(() => budget.AcquireAsync(CloudflareRequestKind.Read));
        Assert.True(full.QueueFull);
        Assert.Equal(2, budget.Snapshot().Queued);

        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(Settle));
        await WaitUntil(() => budget.Snapshot().Queued == 1);
        delays.Advance(TimeSpan.FromMinutes(5));
        await second.WaitAsync(Settle); // moved up after the cancelled call
        Assert.Equal(0, budget.Snapshot().Queued);
    }

    [Fact]
    public async Task M1_reads_waiting_never_hold_up_a_write()
    {
        var clock = new FakeClock(T0);
        var delays = new ManualDelays(clock);
        var budget = Budget(clock, delays.Delay, o => { o.RequestsPerWindow = 10; o.ReadShare = 0.2; o.WriteShare = 1.0; });
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        var read = budget.AcquireAsync(CloudflareRequestKind.Read);
        Assert.False(read.IsCompleted);
        await budget.AcquireAsync(CloudflareRequestKind.Write).WaitAsync(Settle);
        Assert.False(read.IsCompleted);
        delays.Advance(TimeSpan.FromMinutes(5));
        await read.WaitAsync(Settle);
    }

    // ================================================================== M-2: monotonic time

    [Fact]
    public async Task M2_a_wall_clock_jump_forward_frees_no_slot()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, clock.Delay(waits));
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        clock.Advance(TimeSpan.FromMinutes(1));
        clock.JumpWall(TimeSpan.FromHours(1)); // NTP correction or a changed system time
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        Assert.Equal([TimeSpan.FromMinutes(4)], waits); // still the rest of the window, as measured by the monotonic clock
    }

    [Fact]
    public async Task M2_a_wall_clock_jump_back_blocks_no_longer_than_Retry_After()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, clock.Delay(waits), o => o.RequestsPerWindow = 100);
        budget.ReportThrottled(TimeSpan.FromSeconds(30));
        clock.JumpWall(TimeSpan.FromHours(-1));
        // The snapshot shows wall-clock time for display, computed from the remaining monotonic time.
        Assert.Equal(clock.GetUtcNow().AddSeconds(30), budget.Snapshot().BlockedUntil);
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        Assert.Equal([TimeSpan.FromSeconds(30)], waits);
        clock.JumpWall(TimeSpan.FromHours(3));
        Assert.Null(budget.Snapshot().BlockedUntil);
        Assert.Equal(1, budget.Snapshot().UsedInWindow);
    }

    // ================================================================== M-3: client factory

    private static CloudflareOptions Tenant(string token) => new() { ApiToken = token, ZoneId = "zone-a", RetryBaseDelay = TimeSpan.Zero };

    [Fact]
    public void M3_every_setting_change_replaces_the_cached_client()
    {
        Action<CloudflareOptions>[] changes =
        [
            o => o.UserAgent = "other-agent",
            o => o.MaxResponseBytes = 1024,
            o => o.Timeout = TimeSpan.FromSeconds(5),
            o => o.MaxRetries = 0,
            o => o.RetryBaseDelay = TimeSpan.FromSeconds(2),
            o => o.Turnstile.SecretKey = "SYNTHETIC-TURNSTILE-2",
            o => o.Turnstile.ExpectedHostname = "app.example.com",
            o => o.AccessJwt.Audiences.Add("aud-2"),
            o => o.AccessJwt.ClockSkew = TimeSpan.FromSeconds(5),
            o => o.RateBudget.MaxDelay = TimeSpan.FromSeconds(1),
            o => o.RateBudget.MaxQueued = 7,
            o => o.RateBudget.ReadShare = 0.5,
        ];
        foreach (var change in changes)
        {
            var source = Tenant("SYNTHETIC-TOKEN-A");
            source.Turnstile.SecretKey = "SYNTHETIC-TURNSTILE-1";
            source.AccessJwt.Audiences.Add("aud-1");
            using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions> { ["a"] = source }, new FakeHandler());
            var before = factory.GetClient("a");
            Assert.Same(before, factory.GetClient("a"));
            change(source);
            Assert.NotSame(before, factory.GetClient("a"));
        }
    }

    [Fact]
    public void M3_the_settings_text_covers_every_property_but_never_the_token()
    {
        var a = Tenant("SYNTHETIC-TOKEN-A");
        var b = Tenant("SYNTHETIC-TOKEN-B");
        Assert.Equal(a.SettingsText(), b.SettingsText());
        Assert.DoesNotContain("SYNTHETIC-TOKEN", a.SettingsText());
        // Every read-write property of the options and of the nested option objects appears by name.
        foreach (var (prefix, type) in new[] { ("", typeof(CloudflareOptions)), ("Turnstile.", typeof(TurnstileOptions)), ("AccessJwt.", typeof(CloudflareAccessJwtOptions)), ("RateBudget.", typeof(CloudflareRateBudgetOptions)) })
            foreach (var p in type.GetProperties().Where(p => p.CanWrite && p.Name is not (nameof(CloudflareOptions.ApiToken) or nameof(CloudflareOptions.WriteFilter))))
                Assert.Contains(prefix + p.Name, a.SettingsText());
        // A value cannot imitate the next entry (length prefix).
        var c = Tenant("t");
        c.UserAgent = "x;MaxRetries=9";
        Assert.NotEqual(Tenant("t").SettingsText(), c.SettingsText());
    }

    [Fact]
    public void M3_Clone_is_deep()
    {
        var source = Tenant("SYNTHETIC-TOKEN-A");
        source.AccessJwt.Audiences.Add("aud-1");
        var copy = source.Clone();
        AssertNoSharedReferences(source, copy, "CloudflareOptions");
        source.Turnstile.SecretKey = "changed";
        source.AccessJwt.Audiences.Add("aud-2");
        source.RateBudget.MaxDelay = TimeSpan.FromSeconds(1);
        Assert.Equal("", copy.Turnstile.SecretKey);
        Assert.Equal(["aud-1"], copy.AccessJwt.Audiences);
        Assert.Equal(TimeSpan.FromMinutes(5), copy.RateBudget.MaxDelay);
    }

    private static void AssertNoSharedReferences(object a, object b, string path)
    {
        foreach (var p in a.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p.CanWrite && p.GetIndexParameters().Length == 0))
        {
            var va = p.GetValue(a);
            var vb = p.GetValue(b);
            if (va is null || va is string || va is Delegate || p.PropertyType.IsValueType) continue;
            Assert.False(ReferenceEquals(va, vb), $"{path}.{p.Name} is shared between the options and their clone");
            if (va is not IEnumerable) AssertNoSharedReferences(va, vb!, path + "." + p.Name);
        }
    }

    [Fact]
    public async Task M3_parallel_first_calls_get_the_same_client()
    {
        for (var round = 0; round < 20; round++)
        {
            using var factory = new CloudflareClientFactory(new Dictionary<string, CloudflareOptions> { ["a"] = Tenant("SYNTHETIC-TOKEN-A") }, new FakeHandler());
            using var start = new ManualResetEventSlim();
            var tasks = Enumerable.Range(0, 16).Select(_ => Task.Run(() => { start.Wait(); return factory.GetClient("a"); })).ToArray();
            start.Set();
            var clients = await Task.WhenAll(tasks);
            Assert.All(clients, c => Assert.Same(clients[0], c));
        }
    }

    // ================================================================== L-2: reads of a write operation count as writes

    [Fact]
    public async Task L2_the_preparing_read_of_a_removal_draws_from_the_write_share()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = new CloudflareRateBudget(new CloudflareRateBudgetOptions { RequestsPerWindow = 10, ReadShare = 0.2, WriteShare = 1.0 }, "tenant-l2", clock, clock.Delay(waits));
        var h = new FakeHandler
        {
            Responder = (r, _) => r.Method == HttpMethod.Get
                ? FakeHandler.Ok("""[{"id":"m1","status":"accepted","roles":[{"name":"Super Administrator - All Privileges"}]},{"id":"m2","status":"accepted","roles":[{"name":"Administrator"}]}]""", Paging)
                : FakeHandler.Ok("""{"id":"x"}"""),
        };
        var options = new CloudflareOptions { ApiToken = "SYNTHETIC-TOKEN", AccountId = "acc1", AllowWrites = true, RetryBaseDelay = TimeSpan.Zero };
        var cf = new CloudflareClient(new CloudflareApiConnection(new HttpClient(h), options, (_, _) => Task.CompletedTask) { RateBudget = budget });
        await cf.Api.GetRawAsync("zones");
        await cf.Api.GetRawAsync("zones"); // read share (2 of 10) used up
        Assert.True(await cf.Members.RemoveAsync("m2", allowRemoval: true));
        Assert.Empty(waits); // the member list before the DELETE counted as a write
        await cf.Api.GetRawAsync("zones"); // a plain read afterwards is a read again and waits
        Assert.Single(waits);
    }

    [Fact]
    public async Task L2_a_refused_write_leaves_no_write_mark_behind()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = new CloudflareRateBudget(new CloudflareRateBudgetOptions { RequestsPerWindow = 10, ReadShare = 0.1, WriteShare = 1.0 }, "tenant-l2b", clock, clock.Delay(waits));
        var options = new CloudflareOptions { ApiToken = "SYNTHETIC-TOKEN", AccountId = "acc1", AllowWrites = true, RetryBaseDelay = TimeSpan.Zero };
        var cf = new CloudflareClient(new CloudflareApiConnection(new HttpClient(new FakeHandler()), options, (_, _) => Task.CompletedTask) { RateBudget = budget });
        // Former synchronous methods (0.9.0) refused after the guard and left the mark in the caller's flow; since 0.9.1 they are async.
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Gateway.RemoveLocationAsync("loc1"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => cf.Pages.RollbackAsync("site", "d1"));
        await cf.Api.GetRawAsync("zones");
        await cf.Api.GetRawAsync("zones"); // second read: read share is 1 of 10, so it must wait as a read
        Assert.Single(waits);
    }

    // ================================================================== L-3: subscribers, response disposal

    [Fact]
    public async Task L3_a_failing_subscriber_never_breaks_a_request()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, clock.Delay(waits), o => o.RequestsPerWindow = 100);
        budget.Delayed += _ => throw new InvalidOperationException("subscriber bug");
        budget.Throttled += _ => throw new InvalidOperationException("subscriber bug");
        var h = new FakeHandler();
        var limited = FakeHandler.Json("""{"success":false,"errors":[{"code":971,"message":"rate limited"}],"messages":[],"result":null}""", HttpStatusCode.TooManyRequests);
        limited.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(3));
        h.Responses.Enqueue(limited);
        var connection = new CloudflareApiConnection(new HttpClient(h), new CloudflareOptions { ApiToken = "SYNTHETIC-TOKEN", RetryBaseDelay = TimeSpan.Zero }, (_, _) => Task.CompletedTask) { RateBudget = budget };
        await connection.GetRawAsync("zones");
        Assert.Equal(2, h.Requests.Count);
        Assert.Equal([TimeSpan.FromSeconds(3)], waits);
    }

    [Fact]
    public async Task L3_the_handler_reports_429_despite_a_failing_subscriber()
    {
        var clock = new FakeClock(T0);
        var budget = Budget(clock, clock.Delay([]), o => o.RequestsPerWindow = 100);
        budget.Throttled += _ => throw new InvalidOperationException("subscriber bug");
        var inner = new FakeHandler();
        inner.Responses.Enqueue(FakeHandler.Json("{}", HttpStatusCode.TooManyRequests));
        using var http = new HttpClient(new CloudflareRateBudgetHandler(budget) { InnerHandler = inner });
        using var response = await http.GetAsync("https://api.cloudflare.com/client/v4/zones");
        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.NotNull(budget.Snapshot().BlockedUntil);
    }

    // ================================================================== L-4: debugger

    [Fact]
    public void L4_secrets_are_hidden_from_the_debugger()
    {
        var members = typeof(CloudflareOptions).Assembly.GetTypes()
            .SelectMany(t => t.GetMembers(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(m => m is PropertyInfo { PropertyType: var pt } && pt == typeof(string) || m is FieldInfo { FieldType: var ft } && ft == typeof(string))
            .Where(m => !m.Name.Contains("k__BackingField", StringComparison.Ordinal))
            .Where(m => m.Name is "ApiToken" or "SecretKey" or "ClientSecret" or "Secret" || (m.Name == "_value" && m.DeclaringType!.Name.Contains("Secret", StringComparison.Ordinal)))
            .ToList();
        Assert.True(members.Count >= 5, string.Join(", ", members.Select(m => m.DeclaringType!.Name + "." + m.Name)));
        foreach (var m in members)
            Assert.True(m.GetCustomAttribute<DebuggerBrowsableAttribute>()?.State == DebuggerBrowsableState.Never, $"{m.DeclaringType!.Name}.{m.Name} is visible in the debugger");
        Assert.DoesNotContain("SYNTHETIC", new TurnstileOptions { SiteKey = "site", SecretKey = "SYNTHETIC-SECRET" }.ToString());
    }

    // ================================================================== L-5: registry bound, metric labels

    [Fact]
    public async Task L5_idle_budgets_are_removed_and_a_held_budget_comes_back()
    {
        var clock = new FakeClock(T0);
        var registry = new CloudflareRateBudgetRegistry(clock, clock.Delay([])) { MaxBudgets = 2 };
        var b1 = registry.For(Tenant("SYNTHETIC-1"))!;
        await b1.AcquireAsync(CloudflareRequestKind.Read);
        clock.Advance(TimeSpan.FromMinutes(6)); // b1 idle
        var b2 = registry.For(Tenant("SYNTHETIC-2"))!;
        await b2.AcquireAsync(CloudflareRequestKind.Read); // b2 busy
        var b3 = registry.For(Tenant("SYNTHETIC-3"))!;
        Assert.Equal(2, registry.Count); // b1 (idle, least recently used) was removed
        Assert.DoesNotContain(registry.Snapshots(), s => s.Budget == b1.Name);

        // A client that still holds b1 is not lost: its next request re-admits b1, and new clients of the token get the same budget.
        await b1.AcquireAsync(CloudflareRequestKind.Read);
        Assert.Same(b1, registry.For(Tenant("SYNTHETIC-1")));
        Assert.Equal(2, b1.Snapshot().Requests);
        Assert.NotSame(b2, b3);
    }

    [Fact]
    public async Task L5_a_removed_budget_forwards_to_its_successor()
    {
        var clock = new FakeClock(T0);
        var registry = new CloudflareRateBudgetRegistry(clock, clock.Delay([])) { MaxBudgets = 1 };
        var old = registry.For(Tenant("SYNTHETIC-1"))!;
        registry.For(Tenant("SYNTHETIC-2")); // old is idle and goes
        var successor = registry.For(Tenant("SYNTHETIC-1"))!; // new budget for the same token
        Assert.NotSame(old, successor);
        await old.AcquireAsync(CloudflareRequestKind.Write); // counted in the successor: no split of the token's budget
        Assert.Equal(1, successor.Snapshot().Requests);
        Assert.Equal(0, old.Snapshot().Requests);
    }

    [Fact]
    public void L5_metric_labels_are_bounded()
    {
        var labels = Enumerable.Range(0, CloudflareRateBudget.MaxMetricLabels + 5).Select(i => CloudflareRateBudget.Label($"l5-{Guid.NewGuid():N}-{i}")).ToList();
        Assert.Equal("other", labels[^1]);
        Assert.True(labels.Distinct().Count() <= CloudflareRateBudget.MaxMetricLabels + 1);
    }

    // ================================================================== L-6: Pages and Workflows strip secrets as well

    [Fact]
    public async Task L6_pages_and_workflows_answers_lose_secret_looking_members_too()
    {
        var (cf, h, _) = FakeHandler.Create();
        h.Responder = (r, _) => r.RequestUri!.AbsolutePath switch
        {
            var p when p.EndsWith("/pages/projects/site") => FakeHandler.Ok("""{"id":"p1","name":"site","source":{"config":{"deploy_secret":"SYNTHETIC-DEPLOY","password":"SYNTHETIC-PW"}}}"""),
            var p when p.Contains("/instances/i1") => FakeHandler.Ok("""{"id":"i1","status":"running","trigger":{"access_token":"SYNTHETIC-AT"}}"""),
            _ => FakeHandler.Ok("""[{"id":"d1","environment":"production","meta":{"client_secret":"SYNTHETIC-CS"}}]""", """{"page":1,"per_page":25,"total_pages":1}"""),
        };
        var all = System.Text.Json.JsonSerializer.Serialize(new object?[]
        {
            await cf.Pages.GetProjectAsync("site"),
            await cf.Pages.ListDeploymentsAsync("site"),
            await cf.Workflows.GetInstanceAsync("orders", "i1"),
        });
        foreach (var leaked in new[] { "SYNTHETIC-DEPLOY", "SYNTHETIC-PW", "SYNTHETIC-AT", "SYNTHETIC-CS" })
            Assert.DoesNotContain(leaked, all);
        Assert.Contains("running", all);
    }

    // ================================================================== L-7: Retry-After as HTTP date

    [Fact]
    public async Task L7_Retry_After_as_HTTP_date_blocks_the_budget_for_that_long()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, clock.Delay(waits), o => o.RequestsPerWindow = 100);
        var inner = new FakeHandler();
        var limited = FakeHandler.Json("{}", HttpStatusCode.TooManyRequests);
        limited.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(T0.AddSeconds(45));
        inner.Responses.Enqueue(limited);
        using var http = new HttpClient(new CloudflareRateBudgetHandler(budget) { InnerHandler = inner });
        (await http.GetAsync("https://api.cloudflare.com/client/v4/zones")).Dispose();
        Assert.Equal(T0.AddSeconds(45), budget.Snapshot().BlockedUntil);

        // The curated connection reads the date with the budget's clock as well.
        var h = new FakeHandler();
        var again = FakeHandler.Json("""{"success":false,"errors":[],"messages":[],"result":null}""", HttpStatusCode.TooManyRequests);
        again.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(clock.GetUtcNow().AddSeconds(20));
        h.Responses.Enqueue(again);
        var budget2 = Budget(clock, clock.Delay(waits), o => o.RequestsPerWindow = 100);
        var connection = new CloudflareApiConnection(new HttpClient(h), new CloudflareOptions { ApiToken = "SYNTHETIC-TOKEN", RetryBaseDelay = TimeSpan.Zero }, (_, _) => Task.CompletedTask) { RateBudget = budget2 };
        await connection.GetRawAsync("zones");
        Assert.Equal(TimeSpan.FromSeconds(20), waits[^1]);
    }

    // ================================================================== L-8: test gaps

    /// <summary>Every method of every curated client that hits <c>WriteFilter</c> has sent nothing before, not even a preparing read.</summary>
    [Fact]
    public async Task L8_WriteFilter_is_checked_before_every_preparing_read_of_all_clients()
    {
        var violations = new List<string>();
        var guarded = 0;
        foreach (var m in ClientSurface.Methods())
        {
            var (client, h, _) = FakeHandler.Create(o => { o.AllowWrites = true; o.WriteFilter = (_, _) => false; });
            var ex = await ClientSurface.InvokeAsync(m.Client.GetValue(client)!, m.Method, ClientSurface.Arguments(m.Method));
            if (ex is TimeoutException) violations.Add($"{ClientSurface.Name(m)}: timed out");
            foreach (var r in h.Requests.Where(r => r.Method != HttpMethod.Get && !r.Url.EndsWith("/graphql", StringComparison.Ordinal)))
                violations.Add($"{ClientSurface.Name(m)}: sent {r.Method} {r.Url}");
            if (ex is CloudflareWriteNotAllowedException)
            {
                guarded++;
                if (h.Requests.Count > 0) violations.Add($"{ClientSurface.Name(m)}: read {h.Requests.Count}x before WriteFilter refused ({string.Join(", ", h.Requests.Select(r => r.Url))})");
            }
        }
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
        Assert.True(guarded >= 150, $"only {guarded} methods reached the write filter");
    }

    [Fact]
    public async Task L8_single_dot_ids_send_nothing()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        Func<Task>[] calls =
        [
            () => cf.Members.RemoveAsync(".", allowRemoval: true),
            () => cf.SecretsStore.DeleteSecretAsync("st1", ".", allowDelete: true),
            () => cf.SecretsStore.DeleteSecretAsync(".", "s1", allowDelete: true),
            () => cf.Workflows.ChangeInstanceStatusAsync(".", "i1", WorkflowInstanceAction.Pause),
            () => cf.Pages.RollbackAsync("site", ".", allowDeploy: true),
            () => cf.Hyperdrive.DeleteAsync(".", allowDelete: true),
            () => cf.Radar.GetAsync("./ranking"),
            () => cf.Radar.GetAsync("http/./summary"),
        ];
        foreach (var call in calls) await Assert.ThrowsAsync<ArgumentException>(call);
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task L8_Workflows_ChangeInstanceStatus_is_reached_by_the_reflective_surface()
    {
        Assert.Empty(CoverageMatrix.Scenarios);
        var m = Assert.Single(ClientSurface.Methods(), m => m.Client.Name == "Workflows" && m.Method.Name == "ChangeInstanceStatusAsync");
        var (_, h, options) = FakeHandler.Create(o => o.AllowWrites = true);
        var spy = new RecordingConnection(new CloudflareApiConnection(new HttpClient(h), options, (_, _) => Task.CompletedTask));
        Assert.Null(await ClientSurface.InvokeAsync(m.Client.GetValue(new CloudflareClient(spy))!, m.Method, ClientSurface.Arguments(m.Method)));
        Assert.Equal(("PATCH", "accounts/acc1/workflows/name1/instances/id1/status"), Assert.Single(spy.Calls));
    }

    [Fact]
    public async Task L8_cancelling_while_blocked_by_429_sends_nothing_and_frees_the_place()
    {
        var clock = new FakeClock(T0);
        var delays = new ManualDelays(clock);
        var budget = Budget(clock, delays.Delay, o => o.RequestsPerWindow = 100);
        budget.ReportThrottled(TimeSpan.FromSeconds(30));
        using var cancel = new CancellationTokenSource();
        var waiting = budget.AcquireAsync(CloudflareRequestKind.Read, cancel.Token);
        await WaitUntil(() => delays.Pending == 1);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(Settle));
        Assert.Equal(0, budget.Snapshot().Queued);
        Assert.Equal(0, budget.Snapshot().Requests);
    }
}

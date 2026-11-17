using System.Diagnostics.Metrics;
using System.Net;
using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>A clock the test moves by hand.</summary>
internal sealed class FakeClock(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _now = start;
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan by) => _now += by;
    /// <summary>A delay that moves the clock instead of sleeping, and records the wait.</summary>
    public Func<TimeSpan, CancellationToken, Task> Delay(List<TimeSpan> waits) => (t, _) => { waits.Add(t); Advance(t); return Task.CompletedTask; };
}

/// <summary>P6 (0.9.0): shared request budget per token (1200 requests per five minutes at Cloudflare). Fake clock, fake handler, no network.</summary>
public class RateBudgetTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 17, 8, 0, 0, TimeSpan.Zero);

    private static CloudflareRateBudget Budget(FakeClock clock, List<TimeSpan> waits, Action<CloudflareRateBudgetOptions>? configure = null)
    {
        var o = new CloudflareRateBudgetOptions { RequestsPerWindow = 10, Window = TimeSpan.FromMinutes(5), ReadShare = 0.8, WriteShare = 1.0 };
        configure?.Invoke(o);
        return new CloudflareRateBudget(o, "tenant-a", clock, clock.Delay(waits));
    }

    [Fact]
    public async Task Reads_wait_for_the_oldest_slot_instead_of_failing()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, waits);
        for (var i = 0; i < 8; i++) { await budget.AcquireAsync(CloudflareRequestKind.Read); clock.Advance(TimeSpan.FromSeconds(10)); }
        Assert.Empty(waits);
        // The ninth read exceeds the read share (8 of 10): it waits until the first request (at T0) leaves the window.
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        Assert.Equal(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(80), Assert.Single(waits));
        Assert.Equal(8, budget.Snapshot().UsedInWindow);
        Assert.Equal(1, budget.Snapshot().Delays);
    }

    [Fact]
    public async Task Writes_keep_their_headroom_when_reads_have_used_their_share()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, waits);
        for (var i = 0; i < 8; i++) await budget.AcquireAsync(CloudflareRequestKind.Read);
        await budget.AcquireAsync(CloudflareRequestKind.Write);
        await budget.AcquireAsync(CloudflareRequestKind.Write);
        Assert.Empty(waits);
        Assert.Equal(8, budget.ReadLimit);
        Assert.Equal(10, budget.WriteLimit);
    }

    [Fact]
    public async Task A_wait_longer_than_MaxDelay_fails_before_anything_is_sent()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, waits, o => o.MaxDelay = TimeSpan.FromSeconds(30));
        for (var i = 0; i < 8; i++) await budget.AcquireAsync(CloudflareRequestKind.Read);
        var ex = await Assert.ThrowsAsync<CloudflareRateBudgetExceededException>(() => budget.AcquireAsync(CloudflareRequestKind.Read));
        Assert.Equal("tenant-a", ex.Budget);
        Assert.Empty(waits);
    }

    [Fact]
    public async Task A_429_blocks_every_request_of_the_token_until_Retry_After()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, waits);
        var events = new List<CloudflareRateBudgetEvent>();
        budget.Throttled += events.Add;
        budget.ReportThrottled(TimeSpan.FromSeconds(42));
        Assert.Equal(T0.AddSeconds(42), budget.Snapshot().BlockedUntil);
        await budget.AcquireAsync(CloudflareRequestKind.Write);
        Assert.Equal(TimeSpan.FromSeconds(42), Assert.Single(waits));
        Assert.Equal("tenant-a", Assert.Single(events).Budget);
    }

    [Fact]
    public async Task Clients_with_the_same_token_share_one_budget_and_other_tokens_have_their_own()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var registry = new CloudflareRateBudgetRegistry(clock, clock.Delay(waits));
        CloudflareClient Client(string token, FakeHandler h)
        {
            var o = new CloudflareOptions { ApiToken = token, ZoneId = "zone1", RetryBaseDelay = TimeSpan.Zero };
            o.RateBudget.RequestsPerWindow = 4;
            o.RateBudget.ReadShare = 1.0;
            return new CloudflareClient(new CloudflareApiConnection(new HttpClient(h), o, (_, _) => Task.CompletedTask) { RateBudget = registry.For(o) });
        }
        var (h1, h2, h3) = (new FakeHandler(), new FakeHandler(), new FakeHandler());
        var a1 = Client("tok-alpha", h1);
        var a2 = Client("tok-alpha", h2);
        var b = Client("tok-beta", h3);
        for (var i = 0; i < 2; i++) { await a1.Api.GetRawAsync("zones/zone1"); await a2.Api.GetRawAsync("zones/zone1"); }
        Assert.Empty(waits);
        await b.Api.GetRawAsync("zones/zone1");
        Assert.Empty(waits);
        await a2.Api.GetRawAsync("zones/zone1"); // fifth request of token-a in the window
        Assert.Equal(TimeSpan.FromMinutes(5), Assert.Single(waits));
        Assert.Equal(2, registry.Count);
        Assert.All(registry.Snapshots(), s => Assert.DoesNotContain("alpha", s.Budget + s));
        Assert.All(registry.Snapshots(), s => Assert.DoesNotContain("beta", s.Budget + s));
    }

    [Fact]
    public async Task The_connection_reports_a_429_to_the_budget()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var budget = Budget(clock, waits);
        var h = new FakeHandler();
        var limited = FakeHandler.Json("""{"success":false,"errors":[{"code":971,"message":"rate limited"}],"messages":[],"result":null}""", HttpStatusCode.TooManyRequests);
        limited.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(20));
        h.Responses.Enqueue(limited);
        var o = new CloudflareOptions { ApiToken = "secret-token-123", RetryBaseDelay = TimeSpan.Zero };
        var connection = new CloudflareApiConnection(new HttpClient(h), o, (_, _) => Task.CompletedTask) { RateBudget = budget };
        await connection.GetRawAsync("zones");
        Assert.Equal(2, h.Requests.Count);
        Assert.Equal(TimeSpan.FromSeconds(20), Assert.Single(waits)); // the retry waited in the budget for Retry-After
    }

    [Fact]
    public async Task Events_snapshots_and_metrics_carry_the_label_never_the_token()
    {
        var clock = new FakeClock(T0);
        var waits = new List<TimeSpan>();
        var registry = new CloudflareRateBudgetRegistry(clock, clock.Delay(waits));
        var o = new CloudflareOptions { ApiToken = "secret-token-123" };
        o.RateBudget.RequestsPerWindow = 1;
        var budget = registry.For(o)!;
        var events = new List<CloudflareRateBudgetEvent>();
        budget.Delayed += events.Add;
        var measured = new List<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (i, l) => { if (i.Meter.Name == "InfinitySuite360.Cloudflare") l.EnableMeasurementEvents(i); };
        listener.SetMeasurementEventCallback<long>((i, _, tags, _) => measured.Add(i.Name + string.Join(",", tags.ToArray().Select(t => $"{t.Key}={t.Value}"))));
        listener.Start();
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        await budget.AcquireAsync(CloudflareRequestKind.Read);
        var text = JsonSerializer.Serialize(events) + JsonSerializer.Serialize(budget.Snapshot()) + budget + registry + string.Join(";", measured) + o;
        Assert.DoesNotContain("secret-token-123", text);
        Assert.StartsWith("token-", budget.Name);
        Assert.Single(events);
        Assert.Contains(measured, m => m.StartsWith("cloudflare.budget.delays", StringComparison.Ordinal));
    }

    [Fact]
    public void Disabled_budget_or_missing_token_means_no_counting()
    {
        var registry = new CloudflareRateBudgetRegistry();
        var off = new CloudflareOptions { ApiToken = "t" };
        off.RateBudget.Enabled = false;
        Assert.Null(registry.For(off));
        Assert.Null(registry.For(new CloudflareOptions()));
    }

    [Theory]
    [InlineData(0, 0.8, 0.95)]
    [InlineData(1200, 0, 0.95)]
    [InlineData(1200, 0.8, 1.5)]
    public void Invalid_budget_settings_are_refused(int perWindow, double read, double write)
    {
        var o = new CloudflareOptions { ApiToken = "t" };
        o.RateBudget.RequestsPerWindow = perWindow;
        o.RateBudget.ReadShare = read;
        o.RateBudget.WriteShare = write;
        Assert.Throws<CloudflareConfigurationException>(o.Validate);
    }

    [Fact]
    public void Defaults_are_cautious()
    {
        var o = new CloudflareRateBudgetOptions();
        Assert.True(o.Enabled);
        Assert.Equal(1200, o.RequestsPerWindow);
        Assert.Equal(TimeSpan.FromMinutes(5), o.Window);
        var b = new CloudflareRateBudget(o, "x");
        Assert.Equal(960, b.ReadLimit);
        Assert.Equal(1140, b.WriteLimit);
    }
}

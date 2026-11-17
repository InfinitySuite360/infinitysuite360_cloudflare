using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>H-1 (0.7.1): an id such as ".." must never address another endpoint. Fake handler only, no network.</summary>
public class PathTraversalTests
{
    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    [InlineData(" .. ")]
    [InlineData("%2e%2e")]
    [InlineData("%2E.")]
    [InlineData("%252e%252e")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a\nb")]
    [InlineData("a\0b")]
    public void Of_refuses_unsafe_segments(string segment) =>
        Assert.Throws<ArgumentException>(() => CloudflarePath.Of("zones", "zone1", "dns_records", segment));

    [Fact]
    public void Of_encodes_ordinary_segments_and_Append_keeps_a_slash_inside_one_segment()
    {
        Assert.Equal("zones/zone1/dns_records/a%20b%3Fc", CloudflarePath.Of("zones", "zone1", "dns_records", "a b?c"));
        Assert.Equal("accounts/acc1/storage/kv/namespaces/ns/values/dir%2Ffile..txt", CloudflarePath.Append("accounts/acc1/storage/kv/namespaces/ns/values", "dir/file..txt"));
        Assert.Throws<ArgumentException>(() => CloudflarePath.Append("x", ".."));
        Assert.Throws<ArgumentException>(() => CloudflarePath.Append("x", "%2e%2e"));
    }

    [Fact]
    public async Task Deleting_a_record_with_id_dotdot_sends_nothing()
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Dns.DeleteAsync(".."));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Dns.DeleteIfExistsAsync("%2e%2e"));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Dns.GetAsync(".."));
        Assert.Empty(h.Requests);
    }

    [Theory]
    [InlineData("zones/zone1/dns_records/..")]
    [InlineData("zones/zone1/dns_records/../..")]
    [InlineData("zones/zone1/dns_records/%2e%2e")]
    [InlineData("zones/zone1/dns_records/%2E%2E%2F%2E%2E")]
    [InlineData("zones/zone1/./dns_records")]
    [InlineData("zones//dns_records")]
    [InlineData("zones/zone1\\..\\x")]
    public async Task Raw_api_paths_with_dot_segments_are_refused_for_reads_and_writes(string path)
    {
        var (cf, h, _) = FakeHandler.Create(o => o.AllowWrites = true);
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Api.SendAsync<JsonElement>(HttpMethod.Delete, path));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Api.SendAsync<JsonElement>(HttpMethod.Get, path));
        await Assert.ThrowsAsync<ArgumentException>(() => cf.Api.GetRawAsync(path));
        Assert.Empty(h.Requests);
    }

    [Fact]
    public async Task The_write_filter_sees_the_path_as_Cloudflare_resolves_it()
    {
        var seen = new List<string>();
        var (cf, h, _) = FakeHandler.Create(o =>
        {
            o.AllowWrites = true;
            o.WriteFilter = (_, p) => { seen.Add(p); return p.StartsWith("zones/zone1/dns_records/", StringComparison.Ordinal); };
        });
        await cf.Dns.DeleteAsync("r1");
        Assert.Equal(["zones/zone1/dns_records/r1"], seen);
        Assert.Single(h.Requests);
        // The guard check itself refuses a path that would resolve elsewhere, before the filter is asked.
        Assert.Throws<ArgumentException>(() => CloudflareWritePolicy.EnsureAllowed(HttpMethod.Delete, "zones/zone1/dns_records/r1/..", new CloudflareOptions { AllowWrites = true }));
    }

    [Fact]
    public void The_openapi_guard_handler_checks_the_resolved_path()
    {
        var options = new CloudflareOptions { AllowWrites = true, WriteFilter = (_, p) => p.StartsWith("zones/zone1/dns_records/", StringComparison.Ordinal) };
        // new Uri resolves the dots before the handler sees them: the filter must see zones/zone1/ and refuse.
        var uri = new Uri("https://api.cloudflare.com/client/v4/zones/zone1/dns_records/..");
        Assert.Equal("zones/zone1/", CloudflareWritePolicy.RelativePath(uri, options));
        Assert.Throws<CloudflareWriteNotAllowedException>(() => CloudflareWritePolicy.EnsureAllowed(HttpMethod.Delete, CloudflareWritePolicy.RelativePath(uri, options), options));
    }

    /// <summary>Every public method of every curated client, called with ".." for every string: no path with a dot segment reaches the connection.</summary>
    [Fact]
    public async Task No_public_method_builds_a_path_with_a_dot_segment_from_an_id()
    {
        var violations = new List<string>();
        var called = 0;
        foreach (var m in ClientSurface.Methods())
        {
            if (!m.Method.GetParameters().Any(p => p.ParameterType == typeof(string) || p.ParameterType.GetInterfaces().Contains(typeof(IEnumerable<string>)))) continue;
            foreach (var forced in new[] { "..", "%2e%2e", ".", "%2e" }) // "." since 0.9.1 (L-8)
            {
                var (_, h, options) = FakeHandler.Create(o => o.AllowWrites = true);
                var connection = new CloudflareApiConnection(new HttpClient(h), options, (_, _) => Task.CompletedTask);
                var spy = new RecordingConnection(connection);
                var client = new CloudflareClient(spy);
                var ex = await ClientSurface.InvokeAsync(m.Client.GetValue(client)!, m.Method, ClientSurface.Arguments(m.Method, forced));
                called++;
                if (ex is TimeoutException) violations.Add($"{ClientSurface.Name(m)} with {forced}: timed out");
                foreach (var (method, path) in spy.Calls)
                {
                    var segments = CloudflarePath.Normalize(path).Split('/');
                    if (segments.Any(s => s is "." or ".." || Uri.UnescapeDataString(s) is "." or ".."))
                        violations.Add($"{ClientSurface.Name(m)} with {forced}: {method} {path}");
                }
                foreach (var r in h.Requests)
                    if (r.Url.Contains("/../", StringComparison.Ordinal) || r.Url.EndsWith("/..", StringComparison.Ordinal) || r.Url.Contains("%2e", StringComparison.OrdinalIgnoreCase)
                        || r.Url.Contains("/./", StringComparison.Ordinal) || r.Url.EndsWith("/.", StringComparison.Ordinal))
                        violations.Add($"{ClientSurface.Name(m)} with {forced}: sent {r.Method} {r.Url}");
            }
        }
        Assert.True(called > 300, $"only {called} calls");
        Assert.True(violations.Count == 0, string.Join(Environment.NewLine, violations));
    }
}

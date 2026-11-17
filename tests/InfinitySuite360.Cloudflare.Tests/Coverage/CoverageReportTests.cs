namespace InfinitySuite360.Cloudflare.Tests.Coverage;

/// <summary>
/// P6 (0.9.0): the coverage matrix is measured, not maintained by hand, and every request of a curated client is an operation of Cloudflare's schema
/// (contract test against the local schema copy <c>openapi/operations.tsv</c>). Fake handler only, no network.
/// </summary>
public class CoverageReportTests
{
    private static readonly Lazy<Task<List<CoverageMatrix.Call>>> Calls = new(CoverageMatrix.RecordAsync);
    private static readonly Lazy<OperationIndex> Index = new(() => OperationIndex.Load(CoverageMatrix.Root()));

    /// <summary>
    /// L-1 (0.9.1): commit, checksum and operation count are read from the pinned files (lock file, GENERATION.md written by the generator), not written
    /// into the test, so the weekly regeneration (openapi-update.yml) passes for a new schema while a stale operations.tsv still fails.
    /// </summary>
    [Fact]
    public void The_operation_index_is_the_pinned_schema()
    {
        var index = Index.Value;
        var root = CoverageMatrix.Root();
        using var lockFile = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(root, "openapi", "cloudflare-openapi.lock.json")));
        var commit = lockFile.RootElement.GetProperty("commit").GetString()!;
        var sha256 = lockFile.RootElement.GetProperty("sha256").GetString()!;
        Assert.Matches("^[0-9a-f]{40}$", commit);
        Assert.Contains("@" + commit + " ", index.Header);
        Assert.Contains("SHA-256 " + sha256, index.Header);
        Assert.Equal(PinnedOperationCount(), index.Operations.Count);
        Assert.Equal(index.Operations.Count, index.Operations.Distinct().Count());
    }

    /// <summary>The operation count of the generator's report (<c>openapi/GENERATION.md</c>, row "Operations").</summary>
    internal static int PinnedOperationCount()
    {
        var line = File.ReadLines(Path.Combine(CoverageMatrix.Root(), "openapi", "GENERATION.md")).Single(l => l.StartsWith("| Operations |", StringComparison.Ordinal));
        return int.Parse(line.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)[1], System.Globalization.CultureInfo.InvariantCulture);
    }

    [Fact]
    public async Task Coverage_md_is_current()
    {
        var index = Index.Value;
        var (rows, byClient, _) = CoverageMatrix.Build(index, await Calls.Value);
        var expected = CoverageMatrix.Render(index, rows, byClient);
        var path = Path.Combine(CoverageMatrix.Root(), "openapi", "COVERAGE.md");
        if (Environment.GetEnvironmentVariable(CoverageMatrix.WriteVariable) == "1")
        {
            File.WriteAllText(path, expected);
            return;
        }
        var actual = File.ReadAllText(path).Replace("\r\n", "\n");
        Assert.True(actual == expected,
            "openapi/COVERAGE.md is stale: run `dotnet run tools/coverage.cs` and commit the result. First difference at character "
            + Enumerable.Range(0, Math.Min(actual.Length, expected.Length)).FirstOrDefault(i => actual[i] != expected[i], Math.Min(actual.Length, expected.Length)) + ".");
    }

    /// <summary>Contract: every method and path a curated client sends exists in the schema (known deviations listed with a reason).</summary>
    [Fact]
    public async Task Every_request_of_a_curated_client_is_an_operation_of_the_schema()
    {
        var calls = await Calls.Value;
        var (_, _, unmatched) = CoverageMatrix.Build(Index.Value, calls);
        Assert.True(calls.Count > 500, $"only {calls.Count} distinct requests recorded");
        Assert.True(unmatched.Count == 0, "Requests not in the schema:" + Environment.NewLine
            + string.Join(Environment.NewLine, unmatched.Select(u => $"{u.Client}.{u.Member}: {u.Method} {u.Path}").Distinct().Order()));
    }

    /// <summary>A known deviation that no client produces any more must be removed from the list.</summary>
    [Fact]
    public async Task Every_known_deviation_is_still_needed()
    {
        var calls = await Calls.Value;
        foreach (var d in CoverageMatrix.KnownDeviations)
            Assert.True(calls.Any(c => c.Method == d.Method && d.Path.IsMatch(c.Path) && Index.Value.Match(c.Method, c.Path).Count == 0),
                $"Known deviation {d.Method} {d.Path} ({d.Client}) is not produced any more; remove it.");
    }

    [Fact]
    public async Task Every_curated_client_reaches_the_schema_and_priority_1_is_mostly_curated()
    {
        var (rows, byClient, _) = CoverageMatrix.Build(Index.Value, await Calls.Value);
        var clients = typeof(ICloudflareClient).GetProperties().Where(p => typeof(Resources.CloudflareResourceClient).IsAssignableFrom(p.PropertyType)).Select(p => p.Name).ToList();
        var silent = clients.Where(c => !byClient.ContainsKey(c)).ToList();
        Assert.True(silent.Count == 0, "Clients without any matched request: " + string.Join(", ", silent));
        Assert.Equal(Index.Value.Operations.Count, rows.Sum(r => r.Total));
        // The shield products were the reason for P1/P2: Page Shield almost complete, API Shield at least 40 % (the rest is reachable through OpenApi).
        Assert.True(rows.Single(r => r.Area.Name == "Page Shield").Curated * 10 >= rows.Single(r => r.Area.Name == "Page Shield").Total * 8);
        Assert.True(rows.Single(r => r.Area.Name == "API Shield").Curated * 10 >= rows.Single(r => r.Area.Name == "API Shield").Total * 4);
    }

    [Theory]
    [InlineData("GET", "zones/zone1/dns_records", "GET /zones/{zone_id}/dns_records")]
    [InlineData("GET", "zones/zone1/dns_records/export", "GET /zones/{zone_id}/dns_records/export")]
    [InlineData("DELETE", "accounts/acc1/images/v1/img%201", "DELETE /accounts/{account_id}/images/v1/{image_id}")]
    public void Paths_are_matched_to_templates_with_literal_segments_first(string method, string path, string expected) =>
        Assert.Equal(expected, Assert.Single(Index.Value.Match(method, path)).ToString());

    [Fact]
    public void Unknown_paths_and_methods_do_not_match()
    {
        Assert.Empty(Index.Value.Match("GET", "zones/zone1/no_such_thing"));
        Assert.Empty(Index.Value.Match("PATCH", "zones/zone1/dns_records"));
    }

    [Theory]
    [InlineData("/zones/{zone_id}/page_shield/scripts", "Page Shield", 1)]
    [InlineData("/accounts/{account_id}/workers/durable_objects/namespaces", "Pages, Hyperdrive, Workflows, Durable Objects, Secrets Store, builds", 3)]
    [InlineData("/accounts/{account_id}/workers/scripts", "Workers, KV, D1, Queues", 2)]
    [InlineData("/radar/ranking/domain/{domain}", "Radar, intel, Cloudforce One, URL scanner, brand protection", 3)]
    [InlineData("/user", "Users, members, organizations", 3)]
    public void Areas_and_priorities(string template, string area, int priority)
    {
        var a = CoverageMatrix.AreaOf(template);
        Assert.Equal(area, a.Name);
        Assert.Equal(priority, a.Priority);
    }
}

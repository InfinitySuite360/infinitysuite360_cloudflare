using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Tests.Coverage;

/// <summary>One operation of the schema (method and path template, for example <c>GET /zones/{zone_id}/dns_records</c>).</summary>
internal sealed record SchemaOperation(string Method, string Template)
{
    public string[] Segments { get; } = Template.Trim('/').Split('/');
    public override string ToString() => $"{Method} {Template}";
}

/// <summary>The operations of <c>openapi/operations.tsv</c> (written by <c>tools/coverage.cs --index</c> from the pinned schema).</summary>
internal sealed class OperationIndex
{
    private readonly Dictionary<(string Method, int Count), List<SchemaOperation>> _byShape;

    private OperationIndex(string header, List<SchemaOperation> operations)
    {
        Header = header;
        Operations = operations;
        _byShape = operations.GroupBy(o => (o.Method, o.Segments.Length)).ToDictionary(g => g.Key, g => g.ToList());
    }

    public string Header { get; }
    public IReadOnlyList<SchemaOperation> Operations { get; }

    public static OperationIndex Load(string root)
    {
        var lines = File.ReadAllLines(Path.Combine(root, "openapi", "operations.tsv"));
        var header = lines.FirstOrDefault(l => l.StartsWith("# Operations of", StringComparison.Ordinal))?.TrimStart('#', ' ') ?? "";
        var ops = lines.Where(l => l.Length > 0 && l[0] != '#').Select(l => l.Split('\t')).Select(p => new SchemaOperation(p[0], p[1])).ToList();
        return new OperationIndex(header, ops);
    }

    /// <summary>
    /// The schema operations a request matches. A template segment <c>{…}</c> matches any one segment, every other segment must be equal (compared
    /// decoded). A literal match wins over a parameter match (<c>settings/always_use_https</c> before <c>settings/{setting_id}</c>).
    /// </summary>
    public IReadOnlyList<SchemaOperation> Match(string method, string relativePath)
    {
        var segments = CloudflarePath.Normalize(relativePath).TrimEnd('/').Split('/').Select(Unescape).ToArray();
        if (!_byShape.TryGetValue((method, segments.Length), out var candidates)) return [];
        var matches = candidates.Where(o => Fits(o.Segments, segments)).ToList();
        if (matches.Count <= 1) return matches;
        var best = matches.Max(m => m.Segments.Count(s => !IsParameter(s)));
        return matches.Where(m => m.Segments.Count(s => !IsParameter(s)) == best).ToList();
    }

    private static bool Fits(string[] template, string[] path)
    {
        for (var i = 0; i < template.Length; i++)
            if (!IsParameter(template[i]) && !string.Equals(template[i], path[i], StringComparison.Ordinal)) return false;
        return true;
    }

    private static bool IsParameter(string s) => s.StartsWith('{') && s.EndsWith('}');

    private static string Unescape(string s)
    {
        try { return Uri.UnescapeDataString(s); }
        catch (UriFormatException) { return s; }
    }
}

/// <summary>A product area of the matrix with its priority (plan: 1 = operation and protection of gateway and API, 2 = Workers/R2/cache/load balancing, 3 = rest).</summary>
internal sealed record ProductArea(string Name, int Priority, string Note);

/// <summary>A request a curated client sends that is not an operation of the schema, with the reason (contract test exception).</summary>
internal sealed record KnownDeviation(string Method, Regex Path, string Client, string Reason);

/// <summary>Builds the coverage matrix: records every request of every curated method and matches it against the schema.</summary>
internal static class CoverageMatrix
{
    public const string WriteVariable = "CLOUDFLARE_COVERAGE_WRITE";

    public static string Root()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "InfinitySuite360.Cloudflare.sln"))) return dir.FullName;
        throw new InvalidOperationException("Repository root not found.");
    }

    // ------------------------------------------------------------------ areas

    private static readonly ProductArea Other = new("Other (abuse reports, custom pages, web3, tags, …)", 3, "reachable through OpenApi");

    /// <summary>Ordered: the first area whose key matches wins. Keys: <c>a:x</c> = /accounts/{id}/x, <c>z:x</c> = /zones/{id}/x, <c>u:x</c> = /user/x, <c>r:x</c> = /x, <c>re:</c> = regex on the template.</summary>
    private static readonly (ProductArea Area, string[] Keys)[] Areas =
    [
        (new("Audit logs", 3, "AuditLogs (v2), Monitoring (v1)"), ["re:^/accounts/[^/]+/logs/audit", "a:audit_logs", "u:audit_logs", "re:^/organizations/[^/]+/logs/audit"]),
        (new("Pages, Hyperdrive, Workflows, Durable Objects, Secrets Store, builds", 3, "Pages, Hyperdrive, Workflows, DurableObjects, SecretsStore (narrow)"),
            ["re:^/accounts/[^/]+/workers/durable_objects", "a:pages", "r:pages", "a:hyperdrive", "a:workflows", "a:secrets_store", "a:builds", "a:containers", "a:pipelines", "a:artifacts", "a:flagship"]),
        (new("Users, members, organizations", 3, "Members (narrow), Accounts"),
            ["a:members", "a:roles", "a:organizations", "a:shares", "a:oauth_clients", "r:memberships", "r:organizations", "r:tenants", "u:", "u:invites", "u:memberships", "u:organizations", "u:tenants", "u:communication_preferences", "r:oauth"]),
        (new("Accounts, zones, API tokens, zone settings", 1, "Accounts, Zones, ApiTokens"),
            ["r:accounts", "a:", "a:tokens", "a:iam", "a:settings", "a:profile", "a:entitlements", "a:move", "a:subscriptions", "r:zones", "z:", "z:settings", "z:activation_check", "z:hold", "z:available_plans", "z:available_rate_plans", "z:subscription", "z:subscriptions", "z:entitlements", "z:tags", "a:tags", "u:tokens", "r:subscriptions"]),
        (new("DNS (records, DNSSEC, DNS firewall, secondary DNS)", 1, "Dns"),
            ["z:dns_records", "z:dnssec", "z:dns_settings", "z:dns_analytics", "z:secondary_dns", "z:custom_ns", "a:dns_records", "a:dns_settings", "a:dns_firewall", "a:secondary_dns", "a:custom_ns"]),
        (new("SSL/TLS, certificates, mTLS, custom hostnames", 1, "Certificates, Tls, CustomHostnames, OriginPulls, ApiShield (client certificates)"),
            ["z:ssl", "z:acm", "z:custom_certificates", "z:custom_csrs", "z:keyless_certificates", "z:client_certificates", "z:certificate_authorities", "z:origin_tls_client_auth", "z:custom_hostnames", "z:hostnames", "z:ct", "z:dcv_delegation", "a:mtls_certificates", "a:custom_csrs", "r:certificates"]),
        (new("WAF, rulesets, firewall, lists, rate limiting, rules", 1, "Rulesets, Waf, RateLimiting, Lists, IpAccess, Cache rules"),
            ["z:rulesets", "a:rulesets", "z:firewall", "a:firewall", "z:filters", "a:rules", "u:firewall", "z:rate_limits", "z:managed_headers", "z:url_normalization", "z:rate_limit_analytics", "z:snippets"]),
        (new("Bots, leaked credentials, fraud detection", 1, "Bots"), ["z:bot_management", "z:leaked-credential-checks", "z:fraud_detection"]),
        (new("API Shield", 1, "ApiShield"), ["z:api_gateway", "z:schema_validation", "z:token_validation"]),
        (new("Page Shield", 1, "PageShield"), ["z:page_shield"]),
        (new("Zero Trust Access, Tunnel", 1, "Access, Tunnels"), ["a:access", "z:access", "a:cfd_tunnel", "a:tunnels", "a:teamnet", "a:warp_connector", "a:infrastructure"]),
        (new("Zero Trust Gateway, devices, DLP, DEX, email security", 3, "Gateway, Devices, Dlp, RiskScoring (P5)"),
            ["a:gateway", "a:devices", "z:devices", "a:dlp", "a:dex", "a:zt_risk_scoring", "a:email-security", "a:one", "a:data-security", "a:scim", "a:zerotrust", "a:sso_connectors", "a:browser-extension"]),
        (new("Logs, Logpush, analytics, RUM, observability", 1, "Logpush, Monitoring, Analytics"),
            ["z:logpush", "a:logpush", "z:logs", "a:logs", "z:analytics", "a:analytics", "r:analytics", "a:rum", "z:observability", "a:observability", "a:analytics_engine", "u:analytics", "a:request-tracer", "a:diagnostics", "r:graphql"]),
        (new("Notifications", 1, "Monitoring"), ["a:alerting", "a:event_notifications"]),
        (new("Workers, KV, D1, Queues", 2, "Workers, Kv, D1, Queues"), ["a:workers", "z:workers", "r:workers", "a:storage", "a:d1", "a:queues", "a:event_subscriptions", "a:triggers"]),
        (new("R2", 2, "R2"), ["a:r2", "a:r2-catalog", "a:slurper", "a:basin-catalog"]),
        (new("Cache, speed, Argo, Smart Shield, page rules", 2, "Cache, Argo, Zones (purge)"),
            ["z:cache", "z:argo", "a:argo", "u:argo", "z:smart_shield", "z:speed_api", "z:pagerules", "z:purge_cache", "z:invalidate_cache", "z:origin"]),
        (new("Load balancing, health checks, Spectrum, waiting rooms", 2, "LoadBalancing, Spectrum, Monitoring (health checks)"),
            ["a:load_balancers", "z:load_balancers", "u:load_balancers", "u:load_balancing_analytics", "z:healthchecks", "z:spectrum", "u:spectrum_analytics", "z:waiting_rooms", "a:waiting_rooms"]),
        (new("Email Routing", 2, "EmailRouting"), ["z:email", "a:email"]),
        (new("Turnstile, challenges", 1, "Turnstile"), ["a:challenges"]),
        (new("Images, Stream, Realtime, Calls", 3, "Images, Stream (narrow)"), ["a:images", "z:images", "a:stream", "z:stream", "a:realtime", "a:calls", "a:media", "z:media", "a:moq"]),
        (new("Registrar", 3, "Registrar (narrow)"), ["a:registrar", "a:registrar-sandbox"]),
        (new("Magic Transit/WAN, addressing, MNM, CNI, PCAP", 3, "OpenApi only"), ["a:magic", "a:addressing", "z:addressing", "a:mnm", "a:cni", "a:pcaps", "a:connectivity"]),
        (new("Radar, intel, Cloudforce One, URL scanner, brand protection", 3, "Radar (narrow, read-only)"),
            ["r:radar", "a:intel", "z:intel", "a:cloudforce-one", "a:urlscanner", "a:brand-protection", "a:vuln_scanner", "a:cws", "r:cws", "a:security-center", "z:security-center", "a:botnet_feed", "a:abuse-reports", "z:content-upload-scan"]),
        (new("AI (Workers AI, AI Gateway, AI Search, Vectorize)", 3, "OpenApi only (the platform uses its own AI connection)"),
            ["a:ai", "a:ai-gateway", "a:ai-search", "a:autorag", "a:vectorize", "a:agent-memory", "z:ai-security", "z:ai-audit", "a:browser-rendering"]),
        (new("Billing, subscriptions, pay-per-use", 3, "OpenApi only (money)"),
            ["a:billing", "r:billing", "a:billable", "a:billable-usage", "a:invoices", "a:pay-invoice", "a:payment-methods", "a:receipts", "a:pay-per-crawl", "z:pay-per-crawl", "a:pay-per-use", "z:pay-per-use", "a:monetization", "z:monetization", "u:billing", "u:subscriptions"]),
    ];

    public static ProductArea AreaOf(string template)
    {
        var s = template.Trim('/').Split('/');
        string key = s[0] switch
        {
            "accounts" when s.Length >= 2 => "a:" + (s.Length >= 3 ? s[2] : ""),
            "zones" when s.Length >= 2 => "z:" + (s.Length >= 3 ? s[2] : ""),
            "user" => "u:" + (s.Length >= 2 ? s[1] : ""),
            _ => "r:" + s[0],
        };
        foreach (var (area, keys) in Areas)
            foreach (var k in keys)
                if (k.StartsWith("re:", StringComparison.Ordinal) ? Regex.IsMatch(template, k[3..], RegexOptions.CultureInvariant) : k == key)
                    return area;
        return Other;
    }

    public static IEnumerable<ProductArea> AllAreas() => Areas.Select(a => a.Area).Append(Other);

    // ------------------------------------------------------------------ contract exceptions

    /// <summary>Requests of curated methods that are deliberately not schema operations.</summary>
    public static readonly KnownDeviation[] KnownDeviations =
    [
        new("POST", new Regex("^graphql$"), "Analytics", "GraphQL Analytics API: one endpoint outside the REST schema (developers.cloudflare.com/analytics/graphql-api/)."),
        new("GET", new Regex("^accounts/[^/]+/cfd_tunnel/[^/]+/connectors$"), "Tunnels.ListConnectorsAsync",
            "Since 0.1: the schema lists connections (GET …/connections) and one connector (GET …/connectors/{id}), not a connector list. Kept for compatibility; use ListConnectionsAsync (open point)."),
        new("GET", new Regex("^radar/(?!ranking/domain/|entities/asns/)"), "Radar.GetAsync", "Generic Radar access: the dataset path is passed by the caller; the reflective sample is not a real dataset."),
    ];

    // ------------------------------------------------------------------ recording

    /// <summary>(client, method, HTTP method, path) of every request the curated methods send with sample arguments.</summary>
    public sealed record Call(string Client, string Member, string Method, string Path);

    public static async Task<List<Call>> RecordAsync()
    {
        var calls = new List<Call>();
        foreach (var m in ClientSurface.Methods())
            foreach (var responder in Responders)
            {
                var (_, h, options) = FakeHandler.Create(o => o.AllowWrites = true);
                h.Responder = responder;
                var spy = new RecordingConnection(new CloudflareApiConnection(new HttpClient(h), options, (_, _) => Task.CompletedTask));
                await ClientSurface.InvokeAsync(m.Client.GetValue(new CloudflareClient(spy))!, m.Method, ClientSurface.Arguments(m.Method));
                calls.AddRange(spy.Calls.Select(c => new Call(m.Client.Name, m.Method.Name, c.Method, CloudflarePath.Normalize(c.Path))));
            }
        foreach (var (client, member, run) in Scenarios)
        {
            var (_, h, options) = FakeHandler.Create(o => o.AllowWrites = true);
            var spy = new RecordingConnection(new CloudflareApiConnection(new HttpClient(h), options, (_, _) => Task.CompletedTask));
            try { await run(new CloudflareClient(spy)); } catch (Exception) { /* only the requests count */ }
            calls.AddRange(spy.Calls.Select(c => new Call(client, member, c.Method, CloudflarePath.Normalize(c.Path))));
        }
        return calls.Distinct().ToList();
    }

    // Answers that lead the methods down different branches (empty, list, object, list with one item).
    private static readonly Func<HttpRequestMessage, string?, HttpResponseMessage>[] Responders =
    [
        (_, _) => FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":null}"""),
        (r, _) => r.Method == HttpMethod.Get
            ? FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":50,"total_pages":1,"count":0,"total_count":0}}""")
            : FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":{}}"""),
        (_, _) => FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":{}}"""),
        (r, _) => r.Method == HttpMethod.Get
            ? FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":[{"id":"id1","name":"name1"}],"result_info":{"page":1,"per_page":50,"total_pages":1,"count":1,"total_count":1}}""")
            : FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":{"id":"id1"}}"""),
        // 0.9.1: a list item with status and role, so that checks which refuse items without them (Members.RemoveAsync, H-1) still reach their write.
        (r, _) => r.Method == HttpMethod.Get
            ? FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":[{"id":"id1","name":"name1","status":"accepted","roles":[{"id":"r1","name":"Viewer"}]}],"result_info":{"page":1,"per_page":50,"total_pages":1,"count":1,"total_count":1}}""")
            : FakeHandler.Json("""{"success":true,"errors":[],"messages":[],"result":{"id":"id1"}}"""),
    ];

    /// <summary>
    /// Calls whose reflective sample arguments are refused locally, made with valid arguments. Empty since 0.9.1: Workflows.ChangeInstanceStatusAsync takes
    /// an enum and is reached by the reflective surface (L-8). Keep it empty: a method the reflection cannot reach should get typed parameters instead.
    /// </summary>
    internal static readonly (string Client, string Member, Func<CloudflareClient, Task> Run)[] Scenarios = [];

    // ------------------------------------------------------------------ report

    public sealed record Row(ProductArea Area, int Total, int Curated, int Get, int Write);

    public static (List<Row> Rows, Dictionary<string, HashSet<SchemaOperation>> ByClient, List<Call> Unmatched) Build(OperationIndex index, List<Call> calls)
    {
        var covered = new HashSet<SchemaOperation>();
        var byClient = new Dictionary<string, HashSet<SchemaOperation>>(StringComparer.Ordinal);
        var unmatched = new List<Call>();
        foreach (var call in calls)
        {
            var matches = index.Match(call.Method, call.Path);
            if (matches.Count == 0)
            {
                if (!KnownDeviations.Any(d => d.Method == call.Method && d.Path.IsMatch(call.Path))) unmatched.Add(call);
                continue;
            }
            foreach (var op in matches)
            {
                covered.Add(op);
                if (!byClient.TryGetValue(call.Client, out var set)) byClient[call.Client] = set = [];
                set.Add(op);
            }
        }
        var rows = index.Operations.GroupBy(o => AreaOf(o.Template))
            .Select(g => new Row(g.Key, g.Count(), g.Count(covered.Contains), g.Count(o => covered.Contains(o) && o.Method == "GET"), g.Count(o => covered.Contains(o) && o.Method != "GET")))
            .OrderBy(r => r.Area.Priority).ThenByDescending(r => r.Total).ThenBy(r => r.Area.Name, StringComparer.Ordinal)
            .ToList();
        return (rows, byClient, unmatched);
    }

    public static string Render(OperationIndex index, List<Row> rows, Dictionary<string, HashSet<SchemaOperation>> byClient)
    {
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        void L(string line = "") => sb.Append(line).Append('\n');
        var total = rows.Sum(r => r.Total);
        var curated = rows.Sum(r => r.Curated);
        L("# Cloudflare API coverage");
        L();
        L("Generated by `dotnet run tools/coverage.cs` — do not edit; the test `CoverageReportTests` fails when this file is stale.");
        L($"Schema: {index.Header}");
        L();
        L("Every operation of the schema is reachable through the generated client `ICloudflareClient.OpenApi` (package `InfinitySuite360.Cloudflare`).");
        L("**Curated** means a hand-written, tested method of a curated client sends the operation (with write guard, preview, `allow…` switches, secret rules);");
        L("it is measured, not maintained by hand: every public method of every curated client is called with sample arguments against a fake handler and");
        L("each request is matched against `openapi/operations.tsv`. Priority as in the plan: 1 = operation and protection of gateway and API,");
        L("2 = Workers, R2, cache, load balancing, 3 = rest.");
        L();
        L("| | Operations |");
        L("|---|---|");
        L($"| Schema | {total} |");
        L($"| Curated | {curated} ({(total == 0 ? 0 : 100.0 * curated / total).ToString("0.0", inv)} %) |");
        L($"| Only through OpenApi | {total - curated} |");
        L($"| Curated clients | {byClient.Count} |");
        L();
        L("## Coverage per product area");
        L();
        L("| Priority | Area | Operations | Curated | of which GET | of which writes | Only OpenApi | Share | Curated clients |");
        L("|---|---|---|---|---|---|---|---|---|");
        foreach (var r in rows)
            L($"| {r.Area.Priority} | {r.Area.Name} | {r.Total} | {r.Curated} | {r.Get} | {r.Write} | {r.Total - r.Curated} | {(r.Total == 0 ? 0 : 100.0 * r.Curated / r.Total).ToString("0", inv)} % | {r.Area.Note} |");
        foreach (var p in new[] { 1, 2, 3 })
        {
            var t = rows.Where(r => r.Area.Priority == p).Sum(r => r.Total);
            var c = rows.Where(r => r.Area.Priority == p).Sum(r => r.Curated);
            L($"| {p} | **Sum priority {p}** | **{t}** | **{c}** | | | **{t - c}** | **{(t == 0 ? 0 : 100.0 * c / t).ToString("0", inv)} %** | |");
        }
        L();
        L("## Operations per curated client");
        L();
        L("| Client | Operations |");
        L("|---|---|");
        foreach (var (client, ops) in byClient.OrderBy(kv => kv.Key, StringComparer.Ordinal)) L($"| `{client}` | {ops.Count} |");
        L();
        L("## Known deviations (contract test)");
        L();
        L("Requests of curated methods that are not operations of the schema, on purpose:");
        L();
        L("| Method | Path | Client | Reason |");
        L("|---|---|---|---|");
        foreach (var d in KnownDeviations) L($"| {d.Method} | `{d.Path.ToString().Replace("|", @"\|")}` | {d.Client} | {d.Reason} |");
        return sb.ToString();
    }
}

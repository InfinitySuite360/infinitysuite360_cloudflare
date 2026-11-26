using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// A secret that Cloudflare hands out once or that must not be copied around: the client secret of an Access service token, the run token of a
/// Cloudflare Tunnel. Same rules as <see cref="ApiTokenSecret"/>: <see cref="ToString"/> and JSON serialization write <c>[redacted]</c>; read it with
/// <see cref="TakeValue"/> (hands it over and clears this object) or <see cref="Reveal"/>, store it in a secret store at once and never in logs, audit
/// entries or exceptions.
/// </summary>
[JsonConverter(typeof(CloudflareOneTimeSecretConverter))]
public sealed class CloudflareOneTimeSecret : IDisposable
{
    private string? _value;

    internal CloudflareOneTimeSecret(string value, string kind)
    {
        _value = value;
        Kind = kind;
    }

    /// <summary>What the secret is, for example "access-service-token-secret" or "tunnel-run-token" (never the value).</summary>
    public string Kind { get; }

    /// <summary>False after <see cref="TakeValue"/> or <see cref="Dispose"/>.</summary>
    public bool HasValue => _value is not null;

    /// <summary>The value. Throws once the value was taken or disposed.</summary>
    public string Reveal() => _value ?? throw new ObjectDisposedException(nameof(CloudflareOneTimeSecret), "The secret was already taken or disposed.");

    /// <summary>Returns the value and clears it here (one-time hand-over).</summary>
    public string TakeValue()
    {
        var v = Reveal();
        _value = null;
        return v;
    }

    public void Dispose() => _value = null;

    public override string ToString() => $"{Kind}({(HasValue ? P1.Redacted : "taken")})";
}

internal sealed class CloudflareOneTimeSecretConverter : JsonConverter<CloudflareOneTimeSecret>
{
    public override CloudflareOneTimeSecret Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("Secrets are not deserialized.");

    public override void Write(Utf8JsonWriter writer, CloudflareOneTimeSecret value, JsonSerializerOptions options) => writer.WriteStringValue(P1.Redacted);
}

/// <summary>Shared helpers of the 0.8.0 Zero Trust clients (Access, Gateway, Tunnels, devices, DLP).</summary>
internal static class ZT
{
    /// <summary>Members that carry secrets in Zero Trust answers; they are removed before a model is built.</summary>
    public static readonly string[] SecretMembers =
    [
        "client_secret", "secret", "token", "tunnel_secret", "credentials_file", "private_key", "password", "api_key", "access_token", "refresh_token", "seed",
    ];

    /// <summary>
    /// Removes every member whose name is a secret (<see cref="IsSecretName"/>: the names of <see cref="SecretMembers"/> and every name that contains
    /// "secret", "password", "private_key" or "credential"), anywhere in <paramref name="e"/>. L3 (0.8.1): the same rule as <see cref="Redact"/>.
    /// </summary>
    public static JsonElement Strip(JsonElement e)
    {
        if (e.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) return e;
        var node = JsonNode.Parse(e.GetRawText());
        StripNode(node);
        return JsonSerializer.SerializeToElement(node, CloudflareJson.Options);
    }

    private static void StripNode(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var name in o.Select(p => p.Key).Where(IsSecretName).ToList()) o.Remove(name);
                foreach (var child in o.Select(p => p.Value).ToList()) StripNode(child);
                break;
            case JsonArray a:
                foreach (var child in a) StripNode(child);
                break;
        }
    }

    public static async Task<T> SendAsync<T>(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct)
    {
        var response = await api.SendAsync<JsonElement>(method, path, body, ct).ConfigureAwait(false);
        return P1.As<T>(Strip(response.Result));
    }

    /// <summary>The <c>result</c> of a call with secret members removed (for checks that work on the raw answer).</summary>
    public static async Task<JsonElement> ResultAsync(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct) =>
        Strip(await P2.ResultAsync(api, method, path, body, ct).ConfigureAwait(false));

    public static async Task<List<T>> GetListAsync<T>(ICloudflareApiConnection api, string path, CancellationToken ct)
    {
        var result = await P2.ResultAsync(api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        if (result.ValueKind != JsonValueKind.Array) return [];
        return result.EnumerateArray().Select(e => P1.As<T>(Strip(e))).ToList();
    }

    public static async Task<IReadOnlyList<T>> ListAllAsync<T>(ICloudflareApiConnection api, string path, int perPage, CancellationToken ct)
    {
        var list = new List<T>();
        await foreach (var item in api.ListAllAsync<JsonElement>(path, perPage, ct).ConfigureAwait(false))
            list.Add(P1.As<T>(Strip(item)));
        return list;
    }

    /// <summary>
    /// The PUT body of a full replacement: the current object as Cloudflare returned it (without read-only members) with <paramref name="changes"/> laid
    /// over it, so members this package does not model (for example <c>approval_required</c>, <c>mfa_config</c>, <c>schedule</c>, <c>expiration</c>) are
    /// kept instead of being reset by the PUT (H2e/H3, 0.8.1).
    /// </summary>
    public static JsonObject Merge(JsonElement current, JsonObject changes, params string[] readOnly)
    {
        var body = current.ValueKind == JsonValueKind.Object ? (JsonObject)JsonNode.Parse(current.GetRawText())! : new JsonObject();
        foreach (var name in readOnly) body.Remove(name);
        foreach (var name in body.Select(p => p.Key).Where(IsSecretName).ToList()) body.Remove(name);
        foreach (var (name, value) in changes) body[name] = value?.DeepClone();
        return body;
    }

    /// <summary>
    /// True for a Zero Trust wirefilter expression that selects everything (Gateway traffic/identity/posture, device profile match): the tautologies of
    /// <see cref="RulesetRisk.MatchesAll"/> plus <c>any</c>, a field compared with <c>matches ".*"</c>/<c>".+"</c>/<c>"^"</c> or <c>ne ""</c>, a membership in
    /// <c>{0.0.0.0/0 ::/0}</c> and an <c>os.name in {…}</c> with every platform, also behind a top-level <c>or</c>. Syntactic only (no evaluation).
    /// </summary>
    public static bool MatchesAll(string? expression)
    {
        var e = (expression ?? "").Trim();
        if (RulesetRisk.MatchesAll(e)) return true;
        foreach (var part in RulesetRisk.TopLevelOr(e))
        {
            var compact = new string(RulesetRisk.Unwrap(part).Where(c => !char.IsWhiteSpace(c)).ToArray()).ToLowerInvariant();
            if (compact.Length == 0 || BroadZt.IsMatch(compact)) return true;
            if (compact.StartsWith("os.namein{", StringComparison.Ordinal) && Platforms.All(p => compact.Contains($"\"{p}\"", StringComparison.Ordinal))) return true;
        }
        return false;
    }

    private static readonly string[] Platforms = ["windows", "mac", "linux", "android", "ios"];

    private static readonly System.Text.RegularExpressions.Regex BroadZt = new(
        "^(any|all|true|1|[a-z0-9_.\\[\\]*]+(matches|~)\"(\\^|\\.\\*|\\.\\+|\\^\\.\\*|\\^\\.\\+|\\.\\*\\$|\\.\\+\\$|\\^\\.\\*\\$|\\^\\.\\+\\$)\"|"
        + "[a-z0-9_.\\[\\]*]+(ne|!=)\"\"|any\\([a-z0-9_.\\[\\]*]+(ne|!=)\"\"\\)|any\\([a-z0-9_.\\[\\]*]+(matches|~)\"(\\.\\*|\\^\\.\\*\\$|\\.\\+)\"\\)|"
        + "[a-z0-9_.\\[\\]*]+(in|eq)\\{(0\\.0\\.0\\.0/0|::/0)(0\\.0\\.0\\.0/0|::/0)?\\}|any\\([a-z0-9_.\\[\\]*]+in\\{(0\\.0\\.0\\.0/0|::/0)(0\\.0\\.0\\.0/0|::/0)?\\}\\))$",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>A CIDR text that is broad (<see cref="IsBroad"/>); false for anything that is not a CIDR.</summary>
    public static bool IsBroadCidr(string? value)
    {
        try { return IsBroad(Cidr(value, "value")); }
        catch (ArgumentException) { return false; }
    }

    /// <summary>
    /// A Go-style duration ("24h", "30m", "1h30m", "720h", "0s") in seconds; null when it cannot be read. Used to rank session lengths (longer = looser).
    /// </summary>
    public static double? Seconds(string? duration)
    {
        var d = (duration ?? "").Trim().ToLowerInvariant();
        if (d.Length == 0) return null;
        var m = System.Text.RegularExpressions.Regex.Matches(d, @"(\d+(?:\.\d+)?)(ms|s|m|h|d)", System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (m.Count == 0 || string.Concat(m.Select(x => x.Value)) != d) return null;
        double total = 0;
        foreach (System.Text.RegularExpressions.Match x in m)
        {
            var n = double.Parse(x.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
            total += x.Groups[2].Value switch { "ms" => n / 1000, "s" => n, "m" => n * 60, "h" => n * 3600, _ => n * 86400 };
        }
        return total;
    }

    /// <summary>True when <paramref name="next"/> is a longer session than <paramref name="now"/> (or the change cannot be ranked: cautious).</summary>
    public static bool Longer(string? now, string? next)
    {
        if (next is null || string.Equals(now?.Trim(), next.Trim(), StringComparison.OrdinalIgnoreCase)) return false;
        var a = Seconds(now);
        var b = Seconds(next);
        return a is null || b is null || b > a;
    }

    /// <summary>A copy of a JSON value with every member whose name looks like a secret replaced by <c>[redacted]</c> (for previews).</summary>
    public static JsonNode? Redact(JsonNode? node)
    {
        switch (node)
        {
            case null: return null;
            case JsonObject o:
            {
                var copy = new JsonObject();
                foreach (var (name, value) in o)
                    copy[name] = IsSecretName(name) && value is not null ? JsonValue.Create(P1.Redacted) : Redact(value);
                return copy;
            }
            case JsonArray a: return new JsonArray(a.Select(Redact).ToArray());
            default: return node.DeepClone();
        }
    }

    /// <summary>The single rule for secret member names, used by <see cref="Strip"/> (answers) and <see cref="Redact"/> (previews) alike (L3, 0.8.1).</summary>
    public static bool IsSecretName(string name)
    {
        var n = name.ToLowerInvariant();
        return SecretMembers.Contains(n) || n.Contains("secret") || n.Contains("password") || n.Contains("private_key") || n.Contains("credential")
               || n is "token" or "api_key" or "access_token" or "refresh_token" or "seed" or "id_token" or "bearer_token" or "auth_token";
    }

    public static JsonNode? ToNode(object? value) => value switch
    {
        null => null,
        JsonNode n => n.DeepClone(),
        JsonElement e => P1.Node(e),
        _ => JsonSerializer.SerializeToNode(value, value.GetType(), CloudflareJson.Options),
    };

    /// <summary>True when any object in <paramref name="e"/> has a member <paramref name="rule"/> whose member <paramref name="field"/> equals <paramref name="value"/>.</summary>
    public static bool References(JsonElement e, string rule, string field, string value)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in e.EnumerateObject())
                {
                    if (p.Name == rule && p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty(field, out var v)
                        && v.ValueKind == JsonValueKind.String && string.Equals(v.GetString(), value, StringComparison.OrdinalIgnoreCase)) return true;
                    if (References(p.Value, rule, field, value)) return true;
                }
                return false;
            case JsonValueKind.Array:
                return e.EnumerateArray().Any(i => References(i, rule, field, value));
            default:
                return false;
        }
    }

    public static async Task<T?> GetOrNullAsync<T>(ICloudflareApiConnection api, string path, CancellationToken ct) where T : class
    {
        try { return await SendAsync<T>(api, HttpMethod.Get, path, null, ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return null; }
    }

    /// <summary>A CIDR range or single address (normalised text); the prefix length is returned for breadth checks.</summary>
    public static (string Cidr, int Prefix, bool V4) Cidr(string? value, string parameter)
    {
        var v = (value ?? "").Trim();
        var slash = v.IndexOf('/');
        var address = slash < 0 ? v : v[..slash];
        if (!IPAddress.TryParse(address, out var ip)) throw new ArgumentException($"\"{value}\" is not an IP address or CIDR range.", parameter);
        var v4 = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        var max = v4 ? 32 : 128;
        var prefix = max;
        if (slash >= 0 && (!int.TryParse(v[(slash + 1)..], out prefix) || prefix < 0 || prefix > max))
            throw new ArgumentException($"\"{value}\" has an invalid prefix length.", parameter);
        return (slash < 0 ? $"{address}/{max}" : v, prefix, v4);
    }

    /// <summary>A CIDR that covers a large part of the address space (IPv4 shorter than /8, IPv6 shorter than /16, including the default route).</summary>
    public static bool IsBroad((string Cidr, int Prefix, bool V4) c) => c.V4 ? c.Prefix < 8 : c.Prefix < 16;

    public static CloudflareConflictException Conflict(string method, string path, string message) =>
        new(HttpStatusCode.Conflict, method, CloudflarePath.Normalize(path), [new CloudflareError { Message = message }]);

    public static string Plural(int n, string one, string many) => n == 1 ? $"1 {one}" : $"{n} {many}";
}

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>
/// The one shared helper base of the curated clients (0.9.0). It merges the former helper classes <c>P1</c> (0.6.0: member stripping, JSON building,
/// hostname checks), <c>P2</c> (0.7.0: <c>allow…</c> switches, input patterns, hashes) and <c>ZT</c> (0.8.0/0.8.1: the single secret-name rule, merging,
/// breadth checks) without a change of behaviour. Together with <see cref="CloudflareResourceClient"/> (<c>EnsureWritable</c>, <c>EnsureAnyWritable</c>,
/// <c>Preview</c>) it is the pattern every client follows:
/// <list type="number">
/// <item>check inputs locally (<see cref="Required"/>, <see cref="Match"/>, <see cref="Hostname"/>, <see cref="CloudflarePath.Of"/>);</item>
/// <item>check the write guard before any preparing read (<c>EnsureWritable</c>);</item>
/// <item>refuse risky changes unless an <c>allow…</c> switch is set (<see cref="Allow"/>);</item>
/// <item>remove secrets from every answer before a model is built (<see cref="StripSecrets"/>, <see cref="SendSecretFreeAsync{T}"/>, or the named
/// members of <see cref="Strip"/>), and from every preview (<see cref="Redact"/>, <see cref="Mask"/>);</item>
/// <item>offer a <c>Preview…</c> sister that sends nothing (<see cref="CloudflareChangePreview"/>).</item>
/// </list>
/// </summary>
internal static class ResourceKit
{
    // ------------------------------------------------------------------ constants and patterns

    public const string Redacted = "[redacted]";

    private static readonly Regex HostnamePattern = new(@"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Members that carry secrets in answers; they are removed before a model is built (see <see cref="IsSecretName"/>).</summary>
    public static readonly string[] SecretMembers =
    [
        "client_secret", "secret", "token", "tunnel_secret", "credentials_file", "private_key", "password", "api_key", "access_token", "refresh_token", "seed",
    ];

    // ------------------------------------------------------------------ secrets: stripping (answers) and redaction (previews)

    /// <summary>Removes the named members anywhere in <paramref name="element"/> (for example <c>private_key</c>) before it is turned into a model.</summary>
    public static JsonElement Strip(JsonElement element, params string[] names)
    {
        if (element.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) return element;
        var node = JsonNode.Parse(element.GetRawText());
        StripNamed(node, names);
        return JsonSerializer.SerializeToElement(node, CloudflareJson.Options);
    }

    private static void StripNamed(JsonNode? node, string[] names)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var n in names) o.Remove(n);
                foreach (var child in o.Select(p => p.Value).ToList()) StripNamed(child, names);
                break;
            case JsonArray a:
                foreach (var child in a) StripNamed(child, names);
                break;
        }
    }

    /// <summary>
    /// Removes every member whose name is a secret (<see cref="IsSecretName"/>: the names of <see cref="SecretMembers"/> and every name that contains
    /// "secret", "password", "private_key" or "credential"), anywhere in <paramref name="e"/>. L3 (0.8.1): the same rule as <see cref="Redact"/>.
    /// </summary>
    public static JsonElement StripSecrets(JsonElement e)
    {
        if (e.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)) return e;
        var node = JsonNode.Parse(e.GetRawText());
        StripSecretNodes(node);
        return JsonSerializer.SerializeToElement(node, CloudflareJson.Options);
    }

    private static void StripSecretNodes(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var name in o.Select(p => p.Key).Where(IsSecretName).ToList()) o.Remove(name);
                foreach (var child in o.Select(p => p.Value).ToList()) StripSecretNodes(child);
                break;
            case JsonArray a:
                foreach (var child in a) StripSecretNodes(child);
                break;
        }
    }

    /// <summary>The single rule for secret member names, used by <see cref="StripSecrets"/> (answers) and <see cref="Redact"/> (previews) alike (L3, 0.8.1).</summary>
    public static bool IsSecretName(string name)
    {
        var n = name.ToLowerInvariant();
        return SecretMembers.Contains(n) || n.Contains("secret") || n.Contains("password") || n.Contains("private_key") || n.Contains("credential")
               || n is "token" or "api_key" or "access_token" or "refresh_token" or "seed" or "id_token" or "bearer_token" or "auth_token";
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
                    copy[name] = IsSecretName(name) && value is not null ? JsonValue.Create(Redacted) : Redact(value);
                return copy;
            }
            case JsonArray a: return new JsonArray(a.Select(Redact).ToArray());
            default: return node.DeepClone();
        }
    }

    /// <summary>A secret value as it may appear in a preview: <c>[redacted]</c> when set, empty otherwise.</summary>
    public static string Mask(string? value) => string.IsNullOrEmpty(value) ? "" : Redacted;

    // ------------------------------------------------------------------ sending and reading

    public static T As<T>(JsonElement element) => element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null
        ? default!
        : JsonSerializer.Deserialize<T>(element.GetRawText(), CloudflareJson.Options)!;

    /// <summary>The <c>result</c> of an envelope as <see cref="JsonElement"/>.</summary>
    public static async Task<JsonElement> ResultAsync(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct) =>
        (await api.SendAsync<JsonElement>(method, path, body, ct).ConfigureAwait(false)).Result;

    /// <summary>Sends, strips <paramref name="secretMembers"/> from the answer and only then builds the model, so no secret lands in <c>AdditionalData</c>.</summary>
    public static async Task<T> SendStrippedAsync<T>(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct, params string[] secretMembers)
    {
        var response = await api.SendAsync<JsonElement>(method, path, body, ct).ConfigureAwait(false);
        return As<T>(Strip(response.Result, secretMembers));
    }

    public static async Task<IReadOnlyList<T>> ListStrippedAsync<T>(ICloudflareApiConnection api, string path, int perPage, CancellationToken ct, params string[] secretMembers)
    {
        var list = new List<T>();
        await foreach (var item in api.ListAllAsync<JsonElement>(path, perPage, ct).ConfigureAwait(false))
            list.Add(As<T>(Strip(item, secretMembers)));
        return list;
    }

    /// <summary>
    /// Sends, removes the named members (<paramref name="hidden"/>, for example environment variables) and then every secret-looking member
    /// (<see cref="StripSecrets"/>) before the model is built (L-6, 0.9.1: both rules, not only the named list).
    /// </summary>
    public static async Task<T> SendHiddenSecretFreeAsync<T>(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct, params string[] hidden)
    {
        var response = await api.SendAsync<JsonElement>(method, path, body, ct).ConfigureAwait(false);
        return As<T>(StripSecrets(Strip(response.Result, hidden)));
    }

    /// <summary>Every page of a list; each item without the named members and without secret-looking members (L-6, 0.9.1).</summary>
    public static async Task<IReadOnlyList<T>> ListHiddenSecretFreeAsync<T>(ICloudflareApiConnection api, string path, int perPage, CancellationToken ct, params string[] hidden)
    {
        var list = new List<T>();
        await foreach (var item in api.ListAllAsync<JsonElement>(path, perPage, ct).ConfigureAwait(false))
            list.Add(As<T>(StripSecrets(Strip(item, hidden))));
        return list;
    }

    /// <summary>Sends and builds the model from the answer after <see cref="StripSecrets"/> (every secret-looking member removed).</summary>
    public static async Task<T> SendSecretFreeAsync<T>(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct)
    {
        var response = await api.SendAsync<JsonElement>(method, path, body, ct).ConfigureAwait(false);
        return As<T>(StripSecrets(response.Result));
    }

    /// <summary>The <c>result</c> of a call with secret members removed (for checks that work on the raw answer).</summary>
    public static async Task<JsonElement> SecretFreeResultAsync(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct) =>
        StripSecrets(await ResultAsync(api, method, path, body, ct).ConfigureAwait(false));

    public static async Task<List<T>> GetSecretFreeListAsync<T>(ICloudflareApiConnection api, string path, CancellationToken ct)
    {
        var result = await ResultAsync(api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        if (result.ValueKind != JsonValueKind.Array) return [];
        return result.EnumerateArray().Select(e => As<T>(StripSecrets(e))).ToList();
    }

    public static async Task<IReadOnlyList<T>> ListAllSecretFreeAsync<T>(ICloudflareApiConnection api, string path, int perPage, CancellationToken ct)
    {
        var list = new List<T>();
        await foreach (var item in api.ListAllAsync<JsonElement>(path, perPage, ct).ConfigureAwait(false))
            list.Add(As<T>(StripSecrets(item)));
        return list;
    }

    public static async Task<T?> GetSecretFreeOrNullAsync<T>(ICloudflareApiConnection api, string path, CancellationToken ct) where T : class
    {
        try { return await SendSecretFreeAsync<T>(api, HttpMethod.Get, path, null, ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return null; }
    }

    // ------------------------------------------------------------------ guards and input checks

    /// <summary>Throws before anything is sent when a risky option was not switched on deliberately.</summary>
    public static void Allow(bool allowed, string what, string flag)
    {
        if (!allowed) throw new InvalidOperationException($"Refused: {what}. Pass {flag}: true deliberately.");
    }

    public static string Required(string? value, string parameter, int maxLength = 0)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new ArgumentException("A value is required.", parameter);
        if (maxLength > 0 && value.Length > maxLength) throw new ArgumentException($"At most {maxLength} characters.", parameter);
        return value;
    }

    public static string Match(string? value, string parameter, Regex pattern, string rule)
    {
        if (string.IsNullOrWhiteSpace(value) || !pattern.IsMatch(value)) throw new ArgumentException($"\"{value}\" is not valid: {rule}.", parameter);
        return value;
    }

    /// <summary>A bare hostname (lowercase, no scheme, port or path); <paramref name="allowWildcard"/> permits a leading <c>*.</c>.</summary>
    public static string Hostname(string? value, string parameter, bool allowWildcard = false)
    {
        var host = (value ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (host.Length is 0 or > 255 || !HostnamePattern.IsMatch(host) || (!allowWildcard && host.StartsWith("*.", StringComparison.Ordinal)))
            throw new ArgumentException($"\"{value}\" is not a valid hostname (no scheme, port or path{(allowWildcard ? "" : ", no wildcard")}).", parameter);
        return host;
    }

    public static Regex Rx(string pattern) => new(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    public static CloudflareConflictException Conflict(string method, string path, string message) =>
        new(HttpStatusCode.Conflict, method, CloudflarePath.Normalize(path), [new CloudflareError { Message = message }]);

    // ------------------------------------------------------------------ JSON building and comparing

    public static JsonArray Arr(IEnumerable<string> values) => new(values.Select(v => (JsonNode?)JsonValue.Create(v)).ToArray());

    public static JsonNode? Node(JsonElement? element) =>
        element is { } e && e.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null) ? JsonNode.Parse(e.GetRawText()) : null;

    public static JsonNode? Clone(JsonElement? e) => Node(e);

    public static JsonNode? ToNode(object? value) => value switch
    {
        null => null,
        JsonNode n => n.DeepClone(),
        JsonElement e => Node(e),
        _ => JsonSerializer.SerializeToNode(value, value.GetType(), CloudflareJson.Options),
    };

    /// <summary>True when every member of <paramref name="desired"/> is present with the same value in <paramref name="current"/> (Cloudflare adds defaults).</summary>
    public static bool Covers(JsonNode? current, JsonNode? desired)
    {
        if (desired is null) return true;
        if (desired is JsonObject d)
        {
            if (current is not JsonObject c) return false;
            foreach (var (name, value) in d)
            {
                if (value is null) { if (c[name] is not null) return false; continue; }
                if (!c.ContainsKey(name) || !Covers(c[name], value)) return false;
            }
            return true;
        }
        return JsonNode.DeepEquals(current, desired);
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

    /// <summary>True when a JSON element is an object with the member.</summary>
    public static bool TryGet(JsonElement e, string name, out JsonElement value)
    {
        value = default;
        return e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out value);
    }

    public static string? Str(JsonElement e, string name) => TryGet(e, name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

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

    // ------------------------------------------------------------------ texts, sizes, hashes

    public static string Join(IEnumerable<string> items)
    {
        var list = items.ToList();
        return list.Count == 0 ? "none" : string.Join(", ", list);
    }

    public static string Plural(int n, string one, string many) => n == 1 ? $"1 {one}" : $"{n} {many}";

    public static int Utf8(string value) => Encoding.UTF8.GetByteCount(value);

    public static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    public static IEnumerable<T[]> Chunk<T>(IReadOnlyList<T> items, int size)
    {
        for (var i = 0; i < items.Count; i += size) yield return items.Skip(i).Take(size).ToArray();
    }

    // ------------------------------------------------------------------ breadth checks (Zero Trust, routes)

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

    private static readonly Regex BroadZt = new(
        "^(any|all|true|1|[a-z0-9_.\\[\\]*]+(matches|~)\"(\\^|\\.\\*|\\.\\+|\\^\\.\\*|\\^\\.\\+|\\.\\*\\$|\\.\\+\\$|\\^\\.\\*\\$|\\^\\.\\+\\$)\"|"
        + "[a-z0-9_.\\[\\]*]+(ne|!=)\"\"|any\\([a-z0-9_.\\[\\]*]+(ne|!=)\"\"\\)|any\\([a-z0-9_.\\[\\]*]+(matches|~)\"(\\.\\*|\\^\\.\\*\\$|\\.\\+)\"\\)|"
        + "[a-z0-9_.\\[\\]*]+(in|eq)\\{(0\\.0\\.0\\.0/0|::/0)(0\\.0\\.0\\.0/0|::/0)?\\}|any\\([a-z0-9_.\\[\\]*]+in\\{(0\\.0\\.0\\.0/0|::/0)(0\\.0\\.0\\.0/0|::/0)?\\}\\))$",
        RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>A CIDR text that is broad (<see cref="IsBroad"/>); false for anything that is not a CIDR.</summary>
    public static bool IsBroadCidr(string? value)
    {
        try { return IsBroad(Cidr(value, "value")); }
        catch (ArgumentException) { return false; }
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

    /// <summary>
    /// A Go-style duration ("24h", "30m", "1h30m", "720h", "0s") in seconds; null when it cannot be read. Used to rank session lengths (longer = looser).
    /// </summary>
    public static double? Seconds(string? duration)
    {
        var d = (duration ?? "").Trim().ToLowerInvariant();
        if (d.Length == 0) return null;
        var m = Regex.Matches(d, @"(\d+(?:\.\d+)?)(ms|s|m|h|d)", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (m.Count == 0 || string.Concat(m.Select(x => x.Value)) != d) return null;
        double total = 0;
        foreach (Match x in m)
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
}

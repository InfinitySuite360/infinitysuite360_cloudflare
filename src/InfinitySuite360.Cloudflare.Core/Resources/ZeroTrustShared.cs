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

    public static JsonElement Strip(JsonElement e) => P1.Strip(e, SecretMembers);

    public static async Task<T> SendAsync<T>(ICloudflareApiConnection api, HttpMethod method, string path, object? body, CancellationToken ct) =>
        await P1.SendStrippedAsync<T>(api, method, path, body, ct, SecretMembers).ConfigureAwait(false);

    public static async Task<List<T>> GetListAsync<T>(ICloudflareApiConnection api, string path, CancellationToken ct)
    {
        var result = await P2.ResultAsync(api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        if (result.ValueKind != JsonValueKind.Array) return [];
        return result.EnumerateArray().Select(e => P1.As<T>(Strip(e))).ToList();
    }

    public static Task<IReadOnlyList<T>> ListAllAsync<T>(ICloudflareApiConnection api, string path, int perPage, CancellationToken ct) =>
        P1.ListStrippedAsync<T>(api, path, perPage, ct, SecretMembers);

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

    public static bool IsSecretName(string name)
    {
        var n = name.ToLowerInvariant();
        return n.Contains("secret") || n.Contains("password") || n.Contains("private_key") || n is "token" or "api_key" or "access_token" or "refresh_token" or "seed";
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

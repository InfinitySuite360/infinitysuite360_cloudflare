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

    public override string ToString() => $"{Kind}({(HasValue ? ResourceKit.Redacted : "taken")})";
}

internal sealed class CloudflareOneTimeSecretConverter : JsonConverter<CloudflareOneTimeSecret>
{
    public override CloudflareOneTimeSecret Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        throw new NotSupportedException("Secrets are not deserialized.");

    public override void Write(Utf8JsonWriter writer, CloudflareOneTimeSecret value, JsonSerializerOptions options) => writer.WriteStringValue(ResourceKit.Redacted);
}

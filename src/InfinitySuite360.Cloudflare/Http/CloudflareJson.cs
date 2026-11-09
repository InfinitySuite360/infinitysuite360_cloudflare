using System.Text.Json;
using System.Text.Json.Serialization;

namespace InfinitySuite360.Cloudflare.Http;

/// <summary>Shared JSON settings: snake_case like the Cloudflare API, null values are not sent.</summary>
public static class CloudflareJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = null,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
        };
        o.MakeReadOnly(populateMissingResolver: true);
        return o;
    }
}

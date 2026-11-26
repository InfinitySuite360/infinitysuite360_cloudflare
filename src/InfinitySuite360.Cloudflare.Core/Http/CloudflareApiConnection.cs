using System.Net;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace InfinitySuite360.Cloudflare.Http;

/// <summary>Low-level access to any Cloudflare API v4 endpoint. All curated resource clients build on it.</summary>
public interface ICloudflareApiConnection
{
    CloudflareOptions Options { get; }

    /// <summary>JSON call. <paramref name="body"/> may be an object, a <see cref="JsonNode"/>/<see cref="JsonElement"/> or a JSON string.</summary>
    Task<CloudflareResponse<T>> SendAsync<T>(HttpMethod method, string path, object? body = null, CancellationToken ct = default);

    /// <summary>Call with custom content (for example multipart for Workers uploads). The factory runs once per attempt.</summary>
    Task<CloudflareResponse<T>> SendContentAsync<T>(HttpMethod method, string path, Func<HttpContent> content, CancellationToken ct = default);

    /// <summary>Response as raw text (for endpoints without JSON envelope, such as DNS export or Worker source).</summary>
    Task<string> GetRawAsync(string path, CancellationToken ct = default);

    /// <summary>GraphQL Analytics query (read-only). Returns the whole document; GraphQL errors raise an exception.</summary>
    Task<JsonElement> GraphQlAsync(string query, object? variables = null, CancellationToken ct = default);
}

public sealed class CloudflareApiConnection : ICloudflareApiConnection
{
    private readonly HttpClient _http;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public CloudflareApiConnection(HttpClient http, IOptions<CloudflareOptions> options)
        : this(http, options.Value) { }

    public CloudflareApiConnection(HttpClient http, CloudflareOptions options, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _http = http;
        Options = options ?? throw new ArgumentNullException(nameof(options));
        _delay = delay ?? Task.Delay;
    }

    public CloudflareOptions Options { get; }

    /// <summary>
    /// Shared request budget of the token (0.9.0; see <see cref="CloudflareRateBudgetRegistry"/>). When set, every attempt takes a slot first and waits while
    /// the budget is used up; a 429 from Cloudflare blocks the budget until <c>Retry-After</c>. Null: no counting (the default without a registry).
    /// </summary>
    public CloudflareRateBudget? RateBudget { get; init; }

    /// <summary>Describes the connection without the token.</summary>
    public override string ToString() => $"CloudflareApiConnection({Options}, Budget={RateBudget?.Name ?? "none"})";

    public Task<CloudflareResponse<T>> SendAsync<T>(HttpMethod method, string path, object? body = null, CancellationToken ct = default) =>
        SendContentAsync<T>(method, path, () => body is null ? null! : JsonContent(body), ct);

    public async Task<CloudflareResponse<T>> SendContentAsync<T>(HttpMethod method, string path, Func<HttpContent> content, CancellationToken ct = default)
    {
        CloudflareWritePolicy.EnsureAllowed(method, path, Options);
        using var response = await SendWithRetryAsync(method, path, content, ct).ConfigureAwait(false);
        var text = await ReadLimitedAsync(response, ct).ConfigureAwait(false);
        return Parse<T>(method, path, response.StatusCode, text);
    }

    public async Task<string> GetRawAsync(string path, CancellationToken ct = default)
    {
        using var response = await SendWithRetryAsync(HttpMethod.Get, path, () => null!, ct).ConfigureAwait(false);
        var text = await ReadLimitedAsync(response, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) Parse<JsonElement>(HttpMethod.Get, path, response.StatusCode, text);
        return text;
    }

    public async Task<JsonElement> GraphQlAsync(string query, object? variables = null, CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["query"] = query,
            ["variables"] = variables is null ? new JsonObject() : JsonSerializer.SerializeToNode(variables, variables.GetType(), CloudflareJson.Options),
        };
        using var response = await SendWithRetryAsync(HttpMethod.Post, "graphql", () => JsonContent(body), ct).ConfigureAwait(false);
        var text = await ReadLimitedAsync(response, ct).ConfigureAwait(false);
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(text);
            root = doc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new CloudflareApiException(response.StatusCode, "POST", "graphql", [new CloudflareError { Message = "Response is not valid JSON." }], ex);
        }
        if (root.TryGetProperty("errors", out var errors) && errors.ValueKind == JsonValueKind.Array && errors.GetArrayLength() > 0)
        {
            var list = errors.EnumerateArray()
                .Select(e => new CloudflareError { Message = e.TryGetProperty("message", out var m) ? m.GetString() ?? "" : e.ToString() })
                .ToList();
            throw new CloudflareApiException(response.StatusCode, "POST", "graphql", list);
        }
        if (!response.IsSuccessStatusCode)
            throw new CloudflareApiException(response.StatusCode, "POST", "graphql", []);
        return root;
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(HttpMethod method, string path, Func<HttpContent> content, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(Options.ApiToken))
            throw new CloudflareConfigurationException("Cloudflare: no API token configured (CloudflareOptions.ApiToken).");

        CloudflarePath.EnsureSafe(path);
        var uri = CloudflareWritePolicy.ResolveUri(path, Options);
        var idempotent = CloudflareWritePolicy.IsIdempotent(method, path);
        var maxRetries = Math.Clamp(Options.MaxRetries, 0, CloudflareOptions.MaxRetriesLimit);
        // GraphQL Analytics uses POST but only reads; it counts against the read share.
        var kind = CloudflareWritePolicy.IsRead(method) || CloudflarePath.Normalize(path) == "graphql" ? CloudflareRequestKind.Read : CloudflareRequestKind.Write;
        for (var attempt = 0; ; attempt++)
        {
            if (RateBudget is { } budget) await budget.AcquireAsync(kind, ct).ConfigureAwait(false);
            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Options.ApiToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.UserAgent.TryParseAdd(Options.UserAgent);
            request.Content = content();

            var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.TooManyRequests) RateBudget?.ReportThrottled(RetryAfter(response), kind);
            var retryable = response.StatusCode == HttpStatusCode.TooManyRequests
                || (idempotent && response.StatusCode is HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout);
            if (!retryable || attempt >= maxRetries) return response;

            var wait = RetryDelay(response, attempt);
            response.Dispose();
            await _delay(wait, ct).ConfigureAwait(false);
        }
    }

    private static TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        var ra = response.Headers.RetryAfter;
        return ra?.Delta ?? (ra?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
    }

    private TimeSpan RetryDelay(HttpResponseMessage response, int attempt)
    {
        var fromHeader = RetryAfter(response);
        var wait = fromHeader ?? TimeSpan.FromMilliseconds(Options.RetryBaseDelay.TotalMilliseconds * Math.Pow(2, attempt));
        if (wait < TimeSpan.Zero) wait = TimeSpan.Zero;
        return wait > TimeSpan.FromSeconds(60) ? TimeSpan.FromSeconds(60) : wait;
    }

    // Reads the body with an upper bound (CloudflareOptions.MaxResponseBytes): an oversized or endless answer fails instead of filling the memory.
    private async Task<string> ReadLimitedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var limit = Options.MaxResponseBytes;
        var method = response.RequestMessage?.Method.Method ?? "";
        var path = response.RequestMessage?.RequestUri is { } u ? CloudflareWritePolicy.RelativePath(u, Options) : "";
        if (response.Content.Headers.ContentLength is long length && length > limit)
            throw new CloudflareApiException(response.StatusCode, method, path, [new CloudflareError { Message = $"The answer is larger than {limit} bytes (CloudflareOptions.MaxResponseBytes)." }]);
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > limit)
                throw new CloudflareApiException(response.StatusCode, method, path, [new CloudflareError { Message = $"The answer is larger than {limit} bytes (CloudflareOptions.MaxResponseBytes)." }]);
            buffer.Write(chunk, 0, read);
        }
        var charset = response.Content.Headers.ContentType?.CharSet;
        Encoding encoding;
        try { encoding = string.IsNullOrEmpty(charset) ? Encoding.UTF8 : Encoding.GetEncoding(charset.Trim('"')); }
        catch (ArgumentException) { encoding = Encoding.UTF8; }
        var bytes = buffer.GetBuffer();
        var preamble = encoding.GetPreamble();
        var start = preamble.Length > 0 && buffer.Length >= preamble.Length && bytes.AsSpan(0, preamble.Length).SequenceEqual(preamble) ? preamble.Length : 0;
        return encoding.GetString(bytes, start, (int)buffer.Length - start);
    }

    private static HttpContent JsonContent(object body)
    {
        var json = body switch
        {
            string s => s,
            JsonNode n => n.ToJsonString(CloudflareJson.Options),
            JsonElement e => e.GetRawText(),
            _ => JsonSerializer.Serialize(body, body.GetType(), CloudflareJson.Options),
        };
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    internal static CloudflareResponse<T> Parse<T>(HttpMethod method, string path, HttpStatusCode status, string text)
    {
        var normalized = CloudflarePath.Normalize(path);
        if (string.IsNullOrWhiteSpace(text))
        {
            if ((int)status is >= 200 and < 300) return new CloudflareResponse<T> { Success = true };
            throw CloudflareApiException.Create(status, method.Method, normalized, []);
        }

        CloudflareResponse<T>? parsed;
        try { parsed = JsonSerializer.Deserialize<CloudflareResponse<T>>(text, CloudflareJson.Options); }
        catch (JsonException ex)
        {
            throw CloudflareApiException.Create(status, method.Method, normalized, [new CloudflareError { Message = "Response is not valid JSON." }], ex);
        }

        if (parsed is null || !parsed.Success || (int)status is < 200 or >= 300)
            throw CloudflareApiException.Create(status, method.Method, normalized, parsed?.Errors ?? []);
        return parsed;
    }
}

/// <summary>Shortcuts and paging on top of <see cref="ICloudflareApiConnection"/>.</summary>
public static class CloudflareApiConnectionExtensions
{
    public static async Task<T> GetAsync<T>(this ICloudflareApiConnection c, string path, CancellationToken ct = default) =>
        (await c.SendAsync<T>(HttpMethod.Get, path, null, ct).ConfigureAwait(false)).Result!;

    public static async Task<T> PostAsync<T>(this ICloudflareApiConnection c, string path, object? body, CancellationToken ct = default) =>
        (await c.SendAsync<T>(HttpMethod.Post, path, body, ct).ConfigureAwait(false)).Result!;

    public static async Task<T> PutAsync<T>(this ICloudflareApiConnection c, string path, object? body, CancellationToken ct = default) =>
        (await c.SendAsync<T>(HttpMethod.Put, path, body, ct).ConfigureAwait(false)).Result!;

    public static async Task<T> PatchAsync<T>(this ICloudflareApiConnection c, string path, object? body, CancellationToken ct = default) =>
        (await c.SendAsync<T>(HttpMethod.Patch, path, body, ct).ConfigureAwait(false)).Result!;

    public static async Task DeleteAsync(this ICloudflareApiConnection c, string path, CancellationToken ct = default) =>
        await c.SendAsync<JsonElement>(HttpMethod.Delete, path, null, ct).ConfigureAwait(false);

    /// <summary>Reads every page of a list endpoint (page- or cursor-based).</summary>
    public static async IAsyncEnumerable<T> ListAllAsync<T>(this ICloudflareApiConnection c, string path, int perPage = 50,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        string? cursor = null;
        for (var page = 1; page <= 10_000; page++)
        {
            var url = cursor is null
                ? CloudflarePath.WithQuery(path, ("page", page.ToString()), ("per_page", perPage.ToString()))
                : CloudflarePath.WithQuery(path, ("cursor", cursor), ("per_page", perPage.ToString()));
            var response = await c.SendAsync<List<T>>(HttpMethod.Get, url, null, ct).ConfigureAwait(false);
            var items = response.Result ?? [];
            foreach (var item in items) yield return item;

            var info = response.ResultInfo;
            if (items.Count == 0 || info is null) yield break;
            var next = info.Cursors?.After ?? info.Cursor;
            if (info.TotalPages == 0 && !string.IsNullOrEmpty(next))
            {
                if (next == cursor) yield break; // the same cursor again would loop
                cursor = next;
                continue;
            }
            if (cursor is not null) yield break;
            if (info.TotalPages > 0 ? page >= info.TotalPages : items.Count < perPage) yield break;
        }
    }

    /// <summary>Reads every page into a list.</summary>
    public static async Task<IReadOnlyList<T>> ListAllToListAsync<T>(this ICloudflareApiConnection c, string path, int perPage = 50, CancellationToken ct = default)
    {
        var list = new List<T>();
        await foreach (var item in c.ListAllAsync<T>(path, perPage, ct).ConfigureAwait(false)) list.Add(item);
        return list;
    }
}

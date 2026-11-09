using System.Net;
using System.Text;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>Zeichnet Anfragen auf und beantwortet sie aus einer Warteschlange oder per Funktion.</summary>
internal sealed class FakeHandler : HttpMessageHandler
{
    public List<(HttpMethod Method, string Url, string? Body, string? Auth)> Requests { get; } = [];
    public Queue<HttpResponseMessage> Responses { get; } = new();
    public Func<HttpRequestMessage, string?, HttpResponseMessage>? Responder { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        Requests.Add((request.Method, request.RequestUri!.ToString(), body, request.Headers.Authorization?.ToString()));
        if (Responder is not null) return Responder(request, body);
        return Responses.Count > 0 ? Responses.Dequeue() : Json("""{"success":true,"errors":[],"messages":[],"result":null}""");
    }

    public static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Ok(string resultJson, string? resultInfo = null) =>
        Json($$"""{"success":true,"errors":[],"messages":[],"result":{{resultJson}}{{(resultInfo is null ? "" : ",\"result_info\":" + resultInfo)}}}""");

    public static (CloudflareClient Client, FakeHandler Handler, CloudflareOptions Options) Create(Action<CloudflareOptions>? configure = null)
    {
        var handler = new FakeHandler();
        var options = new CloudflareOptions { ApiToken = "secret-token-123", ZoneId = "zone1", AccountId = "acc1", RetryBaseDelay = TimeSpan.Zero };
        configure?.Invoke(options);
        var connection = new CloudflareApiConnection(new HttpClient(handler), options, (_, _) => Task.CompletedTask);
        return (new CloudflareClient(connection), handler, options);
    }
}

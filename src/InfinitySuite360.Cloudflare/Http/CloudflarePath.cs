using System.Text;

namespace InfinitySuite360.Cloudflare.Http;

/// <summary>Safe path and query building: every segment and value is URL-encoded, so an ID can never address another endpoint.</summary>
public static class CloudflarePath
{
    /// <summary>Joins segments into a relative path, for example <c>Of("zones", id, "dns_records")</c>.</summary>
    public static string Of(params string[] segments)
    {
        var sb = new StringBuilder();
        foreach (var s in segments)
        {
            if (string.IsNullOrWhiteSpace(s)) throw new ArgumentException("Empty path segment.", nameof(segments));
            if (sb.Length > 0) sb.Append('/');
            sb.Append(Uri.EscapeDataString(s));
        }
        return sb.ToString();
    }

    /// <summary>Appends query parameters; null values are skipped.</summary>
    public static string WithQuery(string path, IEnumerable<KeyValuePair<string, string?>>? query)
    {
        if (query is null) return path;
        var parts = query.Where(kv => kv.Value is not null)
            .Select(kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value!))
            .ToList();
        if (parts.Count == 0) return path;
        return path + (path.Contains('?') ? "&" : "?") + string.Join("&", parts);
    }

    public static string WithQuery(string path, params (string Key, string? Value)[] query) =>
        WithQuery(path, query.Select(q => new KeyValuePair<string, string?>(q.Key, q.Value)));

    /// <summary>Path without query and leading slash (for allow-lists and error messages).</summary>
    public static string Normalize(string path)
    {
        var p = path.TrimStart('/');
        var q = p.IndexOf('?');
        return q < 0 ? p : p[..q];
    }

    internal static string? Bool(bool? value) => value switch { null => null, true => "true", false => "false" };
}

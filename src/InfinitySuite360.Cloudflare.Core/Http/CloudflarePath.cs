using System.Text;

namespace InfinitySuite360.Cloudflare.Http;

/// <summary>
/// Safe path and query building: every segment and value is URL-encoded, and segments that could address another endpoint are refused before anything is
/// sent: <c>.</c> and <c>..</c> (also percent-encoded, for example <c>%2e%2E</c>), empty segments, control characters, <c>/</c> and <c>\</c>
/// inside one segment. <see cref="Uri.EscapeDataString(string)"/> alone does not encode <c>.</c>, and <c>new Uri(base, path)</c> resolves dot segments,
/// so an id <c>..</c> would otherwise turn <c>zones/{zone}/dns_records/..</c> into <c>zones/{zone}/</c> (0.7.1).
/// </summary>
public static class CloudflarePath
{
    /// <summary>Joins segments into a relative path, for example <c>Of("zones", id, "dns_records")</c>. Throws <see cref="ArgumentException"/> for an unsafe segment.</summary>
    public static string Of(params string[] segments)
    {
        ArgumentNullException.ThrowIfNull(segments);
        var sb = new StringBuilder();
        foreach (var s in segments)
        {
            if (sb.Length > 0) sb.Append('/');
            sb.Append(Uri.EscapeDataString(Segment(s, allowSlash: false)));
        }
        return sb.ToString();
    }

    /// <summary>
    /// Appends one free-form name as a single encoded segment (for example a KV key, which may contain <c>/</c>; it is sent as <c>%2F</c>). Dot segments,
    /// empty names and control characters are refused like in <see cref="Of"/>.
    /// </summary>
    public static string Append(string path, string name) => path.TrimEnd('/') + "/" + Uri.EscapeDataString(Segment(name, allowSlash: true));

    /// <summary>Checks one path segment (before encoding) and returns it unchanged.</summary>
    internal static string Segment(string? s, bool allowSlash)
    {
        if (string.IsNullOrWhiteSpace(s)) throw new ArgumentException("Empty path segment.", "segments");
        if (s.Any(char.IsControl)) throw new ArgumentException("A path segment must not contain control characters.", "segments");
        if (!allowSlash && (s.Contains('/') || s.Contains('\\'))) throw new ArgumentException($"A path segment must not contain '/' or '\\' (\"{Shorten(s)}\").", "segments");
        if (IsDotSegment(s)) throw new ArgumentException($"\"{Shorten(s)}\" is not allowed as a path segment (it would address another endpoint).", "segments");
        return s;
    }

    /// <summary>True for <c>.</c>, <c>..</c> and their percent-encoded forms (also double-encoded), with or without surrounding whitespace.</summary>
    internal static bool IsDotSegment(string segment)
    {
        var s = segment.Trim();
        for (var i = 0; i < 3; i++)
        {
            if (s is "." or "..") return true;
            if (!s.Contains('%')) return false;
            string decoded;
            try { decoded = Uri.UnescapeDataString(s); }
            catch (UriFormatException) { return false; }
            if (decoded == s) return false;
            s = decoded.Trim();
        }
        return s is "." or "..";
    }

    /// <summary>
    /// Throws when a relative path (as given to <see cref="ICloudflareApiConnection"/>) contains a dot segment (also percent-encoded), a backslash, a control
    /// character or an empty interior segment. Paths built with <see cref="Of"/> always pass; this protects raw <c>Api</c> calls.
    /// </summary>
    public static void EnsureSafe(string relativePath)
    {
        ArgumentNullException.ThrowIfNull(relativePath);
        var p = Normalize(relativePath);
        if (p.Contains('\\')) throw new ArgumentException("A path must not contain '\\'.", nameof(relativePath));
        if (p.Any(char.IsControl)) throw new ArgumentException("A path must not contain control characters.", nameof(relativePath));
        var segments = p.Split('/');
        for (var i = 0; i < segments.Length; i++)
        {
            var s = segments[i];
            if (s.Length == 0)
            {
                if (i == segments.Length - 1 && i > 0) continue; // trailing slash
                throw new ArgumentException("A path must not contain empty segments.", nameof(relativePath));
            }
            if (IsDotSegment(s)) throw new ArgumentException("A path must not contain '.' or '..' segments.", nameof(relativePath));
            foreach (var part in DecodedParts(s))
                if (IsDotSegment(part)) throw new ArgumentException("A path must not contain encoded '.' or '..' segments.", nameof(relativePath));
        }
    }

    // A segment such as "%2E%2E%2Fx" decodes to "../x"; check every part between decoded slashes.
    private static IEnumerable<string> DecodedParts(string segment)
    {
        if (!segment.Contains('%')) return [];
        string decoded;
        try { decoded = Uri.UnescapeDataString(segment); }
        catch (UriFormatException) { return []; }
        return decoded.Split('/', '\\');
    }

    private static string Shorten(string s) => s.Length <= 40 ? s : s[..37] + "...";

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

using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;
using InfinitySuite360.Cloudflare.Resources;

namespace InfinitySuite360.Cloudflare.Tests;

/// <summary>Records every path a resource client hands to the connection (before the connection checks it) and forwards the call.</summary>
internal sealed class RecordingConnection(ICloudflareApiConnection inner) : ICloudflareApiConnection
{
    public List<(string Method, string Path)> Calls { get; } = [];
    public CloudflareOptions Options => inner.Options;

    public Task<CloudflareResponse<T>> SendAsync<T>(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        Calls.Add((method.Method, path));
        return inner.SendAsync<T>(method, path, body, ct);
    }

    public Task<CloudflareResponse<T>> SendContentAsync<T>(HttpMethod method, string path, Func<HttpContent> content, CancellationToken ct = default)
    {
        Calls.Add((method.Method, path));
        return inner.SendContentAsync<T>(method, path, content, ct);
    }

    public Task<string> GetRawAsync(string path, CancellationToken ct = default)
    {
        Calls.Add(("GET", path));
        return inner.GetRawAsync(path, ct);
    }

    public Task<JsonElement> GraphQlAsync(string query, object? variables = null, CancellationToken ct = default)
    {
        Calls.Add(("POST", "graphql"));
        return inner.GraphQlAsync(query, variables, ct);
    }
}

/// <summary>Reflection over every public method of the curated resource clients, with sample arguments.</summary>
internal static class ClientSurface
{
    // NullabilityInfoContext is not thread-safe and xUnit runs the reflective tests in parallel: one context per thread.
    private static readonly ThreadLocal<NullabilityInfoContext> NullabilityContext = new(() => new NullabilityInfoContext());
    private static NullabilityInfoContext Nullability => NullabilityContext.Value!;

    /// <summary>(client property, method) for every public instance method declared on a resource client type.</summary>
    public static IEnumerable<(PropertyInfo Client, MethodInfo Method)> Methods()
    {
        foreach (var prop in typeof(ICloudflareClient).GetProperties().Where(p => typeof(CloudflareResourceClient).IsAssignableFrom(p.PropertyType)))
            foreach (var m in prop.PropertyType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                if (m.IsSpecialName || m.IsGenericMethodDefinition || m.GetParameters().Any(p => p.ParameterType.IsByRef)) continue;
                yield return (prop, m);
            }
    }

    public static string Name((PropertyInfo Client, MethodInfo Method) m) =>
        $"{m.Client.Name}.{m.Method.Name}({string.Join(", ", m.Method.GetParameters().Select(p => p.Name))})";

    /// <summary>Invokes the method and waits for it. Returns the exception (unwrapped) or null.</summary>
    public static async Task<Exception?> InvokeAsync(object client, MethodInfo method, object?[] args)
    {
        try
        {
            var result = method.Invoke(client, args);
            if (result is Task task) await task.WaitAsync(TimeSpan.FromSeconds(10));
            return null;
        }
        catch (TargetInvocationException ex) { return ex.InnerException ?? ex; }
        catch (TimeoutException ex) { return ex; }
        catch (Exception ex) { return ex; }
    }

    /// <summary>Arguments for a call. <paramref name="forcedString"/> replaces every string (also inside string collections), for example "..".</summary>
    public static object?[] Arguments(MethodInfo method, string? forcedString = null) =>
        method.GetParameters().Select(p => Sample(p.ParameterType, p.Name ?? "", IsNullable(p), p.HasDefaultValue ? p.DefaultValue : DBNull.Value, forcedString, 0)).ToArray();

    private static bool IsNullable(ParameterInfo p) =>
        Nullable.GetUnderlyingType(p.ParameterType) is not null || (!p.ParameterType.IsValueType && Nullability.Create(p).WriteState == NullabilityState.Nullable);

    private static object? Sample(Type type, string name, bool nullable, object? defaultValue, string? forced, int depth)
    {
        var lower = name.ToLowerInvariant();
        if (type == typeof(CancellationToken)) return CancellationToken.None;
        if (type == typeof(string))
        {
            if (forced is not null) return forced;
            if (nullable && (lower is "zoneid" or "accountid" or "scopeid")) return null;
            return Text(lower);
        }
        if (type == typeof(bool) || type == typeof(bool?)) return true;
        if (Nullable.GetUnderlyingType(type) is { } inner)
            return defaultValue is not DBNull ? defaultValue : Sample(inner, name, false, DBNull.Value, forced, depth + 1);
        if (type.IsEnum) return defaultValue is not DBNull && defaultValue is not null ? Enum.ToObject(type, defaultValue) : Enum.GetValues(type).GetValue(0);
        if (type == typeof(int)) return defaultValue is int i ? i : lower.Contains("port") ? 8443 : lower.Contains("days") ? 365 : 1;
        if (type == typeof(long)) return defaultValue is long l ? l : 1L;
        if (type == typeof(double)) return defaultValue is double d ? d : 1.0;
        if (type == typeof(DateTimeOffset)) return lower.Contains("since") || lower.Contains("start") || lower.Contains("from") ? DateTimeOffset.UtcNow.AddDays(-1) : DateTimeOffset.UtcNow.AddDays(7);
        if (type == typeof(TimeSpan)) return TimeSpan.FromDays(30);
        if (type == typeof(JsonElement)) return JsonSerializer.SerializeToElement(new { a = 1 });
        if (type == typeof(JsonObject) || type == typeof(JsonNode)) return new JsonObject { ["a"] = 1 };
        if (type == typeof(object)) return new JsonObject { ["a"] = 1 };
        if (type == typeof(byte[])) return new byte[] { 1, 2, 3 };
        if (depth > 3) return null;
        if (type == typeof(WorkerSecretText)) return WorkerSecretText.From("SYNTHETIC-SECRET");
        if (type == typeof(JwtKeySet)) return JwtKeySet.Parse("""{"keys":[{"kty":"EC","alg":"ES256","kid":"k1","crv":"P-256","x":"AAAA","y":"BBBB"}]}""");
        if (type == typeof(DnsRecordInput)) return new DnsRecordInput { Type = "A", Name = "app.example.com", Content = "203.0.113.10", Proxied = true };
        if (type == typeof(RulesetRule)) return new RulesetRule { Ref = "r1", Action = "log", Expression = "(http.host eq \"app.example.com\")" };
        if (type == typeof(LbOriginInput)) return new LbOriginInput("o2", "203.0.113.11");

        // Collections of strings or of sample objects.
        if (type.IsArray || (type.IsGenericType && typeof(IEnumerable).IsAssignableFrom(type)))
        {
            var args = type.IsArray ? [type.GetElementType()!] : type.GetGenericArguments();
            if (args.Length == 2 && type.Name.Contains("Dictionary"))
            {
                var dictType = typeof(Dictionary<,>).MakeGenericType(args);
                var dict = (IDictionary)Activator.CreateInstance(dictType)!;
                var key = Sample(args[0], Singular(lower), false, DBNull.Value, forced, depth + 1);
                var value = args[1] == typeof(object) ? "on" : args[1] == typeof(string) ? (lower.Contains("state") ? "review" : lower.Contains("action") ? "log" : "v") : Sample(args[1], Singular(lower), false, DBNull.Value, forced, depth + 1);
                if (key is not null) dict[key] = value;
                return dict;
            }
            if (args.Length != 1) return null;
            var element = args[0];
            var item = element.IsGenericType && element.GetGenericTypeDefinition() == typeof(ValueTuple<,>)
                ? Activator.CreateInstance(element, element.GetGenericArguments().Select((t, i) => Sample(t, i == 0 ? "name" : "metadata", i > 0, DBNull.Value, forced, depth + 1)).ToArray())
                : Sample(element, Singular(lower), false, DBNull.Value, forced, depth + 1);
            var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(element))!;
            if (item is not null) list.Add(item);
            if (type.IsArray)
            {
                var arr = Array.CreateInstance(element, list.Count);
                list.CopyTo(arr, 0);
                return arr;
            }
            return list;
        }

        if (type.IsValueType && type.IsGenericType && type.FullName!.StartsWith("System.ValueTuple`", StringComparison.Ordinal))
            return Activator.CreateInstance(type, type.GetGenericArguments().Select(t => Sample(t, name, false, DBNull.Value, forced, depth + 1)).ToArray());
        if (type.IsValueType) return Activator.CreateInstance(type);

        if (type.IsClass && !type.IsAbstract)
        {
            // Records with a primary constructor: the constructor with the most parameters.
            var ctor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).FirstOrDefault();
            if (ctor is null) return null;
            object? instance;
            try
            {
                instance = ctor.Invoke(ctor.GetParameters().Select(p => Sample(p.ParameterType, p.Name ?? "", IsNullable(p), p.HasDefaultValue ? p.DefaultValue : DBNull.Value, forced, depth + 1)).ToArray());
            }
            catch { return null; }
            if (ctor.GetParameters().Length == 0)
                foreach (var prop in type.GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(p => p.CanWrite && p.GetCustomAttribute<RequiredMemberAttribute>() is not null))
                {
                    try { prop.SetValue(instance, Sample(prop.PropertyType, prop.Name, false, DBNull.Value, forced, depth + 1)); }
                    catch { /* leave default */ }
                }
            return instance;
        }
        return null;
    }

    private static string Singular(string name) => name.EndsWith("ies") ? name[..^3] + "y" : name.EndsWith("es") && name.Length > 4 && name[^3] is 's' or 'x' ? name[..^2] : name.EndsWith('s') ? name[..^1] : name;

    private static string Text(string n)
    {
        if (n.Contains("zoneid")) return "zone1";
        if (n.Contains("accountid")) return "acc1";
        if (n is "originname") return "o1";
        if (n.Contains("domain")) return "app.example.com";
        if (n.Contains("hostname") || n is "host" or "domain" or "origin" or "fallbackorigin" or "server") return "app.example.com";
        if (n.Contains("pattern")) return "example.com/api/*";
        if (n.Contains("url")) return "https://example.com/a.css";
        if (n.Contains("sql")) return "SELECT 1";
        if (n.Contains("expression")) return "(http.host eq \"app.example.com\")";
        if (n.Contains("phase")) return "http_request_firewall_custom";
        if (n.Contains("status")) return "active";
        if (n is "mode") return "strict";
        if (n.Contains("version") || n.Contains("tls")) return "1.2";
        if (n.Contains("settingid")) return "always_use_https";
        if (n.Contains("destination")) return "https://logs.example.com/x";
        if (n.Contains("dataset")) return "http_requests";
        if (n.Contains("action")) return "log";
        if (n.Contains("state")) return "review";
        if (n is "type") return "https";
        if (n.Contains("protocol")) return "tcp/8443";
        if (n.Contains("cron")) return "*/5 * * * *";
        if (n.Contains("email")) return "ops@example.com";
        if (n.Contains("address") || n is "content") return "203.0.113.10";
        if (n.Contains("bucket")) return "bucket1";
        if (n.Contains("prefix")) return "example.com/assets/";
        if (n.Contains("environment")) return "production";
        if (n.Contains("source")) return "export default {};";
        if (n.Contains("method")) return "GET";
        if (n.Contains("endpoint")) return "/api/x";
        if (n.Contains("cidr") || n.Contains("ip")) return "203.0.113.0/24";
        if (n.Contains("description") || n.Contains("title") || n.Contains("comment") || n.Contains("message")) return "text";
        if (n.Contains("tag")) return "t1";
        if (n.Contains("key")) return "k1";
        if (n.Contains("value")) return "v1";
        if (n.EndsWith("id")) return "id1";
        return "name1";
    }
}

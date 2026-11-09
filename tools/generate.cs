// Regenerates src/InfinitySuite360.Cloudflare.OpenApi/Generated from Cloudflare's official OpenAPI schema.
//
//   dotnet run tools/generate.cs              generate from the commit pinned in openapi/cloudflare-openapi.lock.json
//   dotnet run tools/generate.cs -- --update  pin the latest commit of cloudflare/api-schemas first, then generate
//
// Steps: download (cached, SHA-256 verified) -> normalize (openapi/normalization.md) -> Kiota -> openapi/COVERAGE.md

using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

var update = args.Contains("--update");
var root = FindRoot(Directory.GetCurrentDirectory());
var lockPath = Path.Combine(root, "openapi", "cloudflare-openapi.lock.json");
var cacheDir = Path.Combine(root, "openapi", "cache");
Directory.CreateDirectory(cacheDir);
var lockDoc = JsonNode.Parse(File.ReadAllText(lockPath))!.AsObject();
var repository = (string)lockDoc["repository"]!;
var file = (string)lockDoc["file"]!;

using var http = new HttpClient();
http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("InfinitySuite360-Cloudflare-Generator", "1.0"));

if (update)
{
    var commit = JsonNode.Parse(await http.GetStringAsync($"https://api.github.com/repos/{repository}/commits/main"))!;
    lockDoc["commit"] = (string)commit["sha"]!;
    lockDoc["committedAt"] = (string)commit["commit"]!["committer"]!["date"]!;
    lockDoc["sha256"] = null;
    Console.WriteLine($"Pinned {repository}@{lockDoc["commit"]}");
}

var sha = (string)lockDoc["commit"]!;
var specPath = Path.Combine(cacheDir, $"openapi-{sha[..12]}.json");
if (!File.Exists(specPath))
{
    var url = $"https://raw.githubusercontent.com/{repository}/{sha}/{file}";
    Console.WriteLine($"Downloading {url}");
    await File.WriteAllBytesAsync(specPath, await http.GetByteArrayAsync(url));
}
var hash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(specPath))).ToLowerInvariant();
if (lockDoc["sha256"] is null) lockDoc["sha256"] = hash;
else if ((string)lockDoc["sha256"]! != hash)
{
    File.Delete(specPath);
    throw new InvalidOperationException($"SHA-256 mismatch for {file}@{sha}: expected {lockDoc["sha256"]}, got {hash}.");
}
File.WriteAllText(lockPath, lockDoc.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");

// ---- Normalize ----
var doc = JsonNode.Parse(await File.ReadAllTextAsync(specPath))!.AsObject();
var normalizer = new Normalizer(doc);
normalizer.Run();
var normalizedPath = Path.Combine(cacheDir, "openapi.normalized.json");
await File.WriteAllTextAsync(normalizedPath, doc.ToJsonString());
Console.WriteLine("Normalization: " + string.Join(", ", normalizer.Stats.OrderBy(k => k.Key).Select(k => $"{k.Key}={k.Value}")));

// ---- Kiota ----
var output = Path.Combine(root, "src", "InfinitySuite360.Cloudflare.OpenApi", "Generated");
if (!args.Contains("--skip-kiota"))
{
    var exit = Run("dotnet", ["tool", "restore"], root);
    if (exit != 0) throw new InvalidOperationException("dotnet tool restore failed.");
    exit = Run("dotnet", ["kiota", "generate", "-l", "CSharp", "-d", normalizedPath, "-c", "CloudflareApiClient",
        "-n", "InfinitySuite360.Cloudflare.OpenApi", "-o", output, "--exclude-backward-compatible", "--clean-output", "--ll", "Warning"], root);
    if (exit != 0) throw new InvalidOperationException("Kiota generation failed (see output above).");
}

// ---- Post-processing of generated code ----
// P1: a literal path segment "item" becomes a property "Item", which collides with the C# indexer (implicitly named "Item").
//     The indexer gets another metadata name; C# callers still use client[...] unchanged.
var indexerFixes = 0;
foreach (var path in Directory.EnumerateFiles(output, "*RequestBuilder.cs", SearchOption.AllDirectories))
{
    var text = await File.ReadAllTextAsync(path);
    if (!System.Text.RegularExpressions.Regex.IsMatch(text, @"public\s+\S+\s+Item\s*\r?\n\s*\{") || !text.Contains(" this[string position]", StringComparison.Ordinal)
        || text.Contains("IndexerName(", StringComparison.Ordinal)) continue;
    text = System.Text.RegularExpressions.Regex.Replace(text, @"(\r?\n)(\s*)(public\s+\S+\s+this\[string position\])",
        "$1$2[global::System.Runtime.CompilerServices.IndexerName(\"ItemAt\")]$1$2$3");
    await File.WriteAllTextAsync(path, text);
    indexerFixes++;
}
if (indexerFixes > 0) normalizer.Stats["P1 indexer-renamed"] = indexerFixes;

// ---- Coverage report ----
var paths = doc["paths"]!.AsObject();
string[] methods = ["get", "post", "put", "patch", "delete"];
var ops = paths.SelectMany(p => p.Value!.AsObject().Where(m => methods.Contains(m.Key)).Select(m => (Path: p.Key, Method: m.Key, Op: m.Value!.AsObject()))).ToList();
var byArea = ops.GroupBy(o => Area(o.Path)).OrderByDescending(g => g.Count()).ToList();
var files = Directory.GetFiles(output, "*.cs", SearchOption.AllDirectories);
var sb = new StringBuilder();
sb.AppendLine("# Cloudflare API coverage").AppendLine();
sb.AppendLine($"Generated from `{repository}@{sha}` ({lockDoc["committedAt"]}), file `{file}`, SHA-256 `{hash}`.").AppendLine();
sb.AppendLine("| | Count |").AppendLine("|---|---|");
sb.AppendLine($"| Paths | {paths.Count} |");
sb.AppendLine($"| Operations | {ops.Count} |");
foreach (var m in methods) sb.AppendLine($"| {m.ToUpperInvariant()} | {ops.Count(o => o.Method == m)} |");
sb.AppendLine($"| Schemas | {doc["components"]!["schemas"]!.AsObject().Count} |");
sb.AppendLine($"| Generated C# files | {files.Length} |").AppendLine();
sb.AppendLine("Every operation listed in the schema is reachable through `ICloudflareClient.OpenApi`.").AppendLine();
sb.AppendLine("## Normalization").AppendLine();
sb.AppendLine("Rules are described in [normalization.md](normalization.md).").AppendLine();
sb.AppendLine("| Rule | Applied |").AppendLine("|---|---|");
foreach (var s in normalizer.Stats.OrderBy(k => k.Key)) sb.AppendLine($"| {s.Key} | {s.Value} |");
sb.AppendLine().AppendLine("## Operations per area").AppendLine();
sb.AppendLine("| Area | Operations |").AppendLine("|---|---|");
foreach (var g in byArea) sb.AppendLine($"| `{g.Key}` | {g.Count()} |");
await File.WriteAllTextAsync(Path.Combine(root, "openapi", "COVERAGE.md"), sb.ToString());
Console.WriteLine($"Done: {ops.Count} operations, {files.Length} files.");
return 0;

static string Area(string path)
{
    var s = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
    return s.Length switch
    {
        0 => "/",
        _ when s[0] is "accounts" or "zones" or "user" or "organizations" && s.Length > 2 => $"/{s[0]}/{{id}}/{s[2]}",
        _ => "/" + s[0],
    };
}

static int Run(string exe, string[] arguments, string cwd)
{
    var psi = new ProcessStartInfo(exe) { WorkingDirectory = cwd, UseShellExecute = false };
    foreach (var a in arguments) psi.ArgumentList.Add(a);
    using var p = Process.Start(psi)!;
    p.WaitForExit();
    return p.ExitCode;
}

static string FindRoot(string start)
{
    for (var d = new DirectoryInfo(start); d is not null; d = d.Parent)
        if (File.Exists(Path.Combine(d.FullName, "openapi", "cloudflare-openapi.lock.json"))) return d.FullName;
    throw new InvalidOperationException("Run from inside the repository (openapi/cloudflare-openapi.lock.json not found).");
}

/// <summary>
/// Rewrites constructs of the upstream schema that Kiota cannot generate, without changing the wire format.
/// Every rule is generic (no per-schema patches) so the generator keeps working when the schema changes.
/// </summary>
sealed class Normalizer(JsonObject doc)
{
    private static readonly HashSet<string> Primitive = ["string", "integer", "number", "boolean"];
    private static readonly HashSet<string> SkipKeys = ["example", "examples", "default", "enum", "const"];
    private readonly JsonObject _schemas = doc["components"]!["schemas"]!.AsObject();

    public SortedDictionary<string, int> Stats { get; } = new(StringComparer.Ordinal);

    public void Run()
    {
        Walk(doc, propertiesMap: false);
        WildcardPaths();
        CollapseReferenceChains();
    }

    // R9: component schemas that are only a $ref (alias) leave OpenAPI.NET with unresolved references inside allOf.
    // Every reference is pointed at the final target and the aliases are removed.
    private void CollapseReferenceChains()
    {
        const string prefix = "#/components/schemas/";
        var aliases = _schemas.Where(s => s.Value is JsonObject o && o["$ref"] is JsonValue).Select(s => s.Key).ToHashSet(StringComparer.Ordinal);
        if (aliases.Count == 0) return;

        string Final(string name)
        {
            for (var depth = 0; depth < 30 && _schemas[name] is JsonObject o && o["$ref"] is JsonValue r && r.TryGetValue<string>(out var target) && target.StartsWith(prefix, StringComparison.Ordinal); depth++)
                name = target[prefix.Length..];
            return name;
        }

        void Rewrite(JsonNode? node)
        {
            switch (node)
            {
                case JsonObject o:
                    if (o["$ref"] is JsonValue r && r.TryGetValue<string>(out var reference) && reference.StartsWith(prefix, StringComparison.Ordinal)
                        && aliases.Contains(reference[prefix.Length..]))
                        o["$ref"] = prefix + Final(reference[prefix.Length..]);
                    foreach (var (_, value) in o.ToList()) Rewrite(value);
                    break;
                case JsonArray a:
                    foreach (var item in a.ToList()) Rewrite(item);
                    break;
            }
        }

        Rewrite(doc); // runs before any alias is removed, so Final() still sees the whole chain
        foreach (var alias in aliases)
        {
            _schemas.Remove(alias);
            Bump("R9 reference-alias-removed");
        }
    }

    private void Bump(string rule) => Stats[rule] = Stats.GetValueOrDefault(rule) + 1;

    private void Walk(JsonNode? node, bool propertiesMap)
    {
        switch (node)
        {
            case JsonObject map when propertiesMap:
                foreach (var (_, value) in map.ToList()) Walk(value, false);
                break;
            case JsonObject o:
                Fix(o);
                foreach (var (key, value) in o.ToList())
                {
                    if (SkipKeys.Contains(key) || key.StartsWith("x-", StringComparison.Ordinal)) continue;
                    Walk(value, key == "properties" && value is JsonObject);
                }
                break;
            case JsonArray a:
                foreach (var item in a.ToList()) Walk(item, false);
                break;
        }
    }

    private void Fix(JsonObject o)
    {
        // R1: an enum containing "" cannot be named in C#; keep the value space by turning it into a plain string.
        if (o["enum"] is JsonArray e && e.Any(v => v is JsonValue jv && jv.TryGetValue<string>(out var s) && s.Length == 0))
        {
            o.Remove("enum");
            Bump("R1 enum-with-empty-value");
        }

        // R2: an object schema with properties but without "type".
        if (o["properties"] is JsonObject && !o.ContainsKey("type") && !Has(o, "allOf", "oneOf", "anyOf", "$ref"))
        {
            o["type"] = "object";
            Bump("R2 untyped-object");
        }

        // R3: allOf members that cannot be a base class (pure unions or empty objects).
        if (o["allOf"] is JsonArray all && all.Count > 0)
        {
            var own = o["properties"] is JsonObject p && p.Count > 0;
            if (all.Count == 1 && !own && all[0] is JsonObject only && only["$ref"] is not null && !Has(o, "oneOf", "anyOf"))
            {
                var reference = (string)only["$ref"]!;
                foreach (var key in o.Select(k => k.Key).Where(k => k is not ("description" or "title")).ToList()) o.Remove(key);
                o["$ref"] = reference;
                Bump("R3a single-ref-allOf-unwrapped");
            }
            else
            {
                var keep = new List<JsonNode>();
                foreach (var member in all.ToList())
                {
                    var r = Resolve(member);
                    if (member is JsonObject m && m["$ref"] is not null && r is not null && (IsUnionOnly(r) || IsEmptyObject(r)))
                    {
                        o["additionalProperties"] = true;
                        Bump("R3b non-inheritable-base-dropped");
                    }
                    else keep.Add(member!.DeepClone());
                }
                if (keep.Count > 0) o["allOf"] = new JsonArray([.. keep]);
                else
                {
                    o.Remove("allOf");
                    o["type"] ??= "object";
                    if (o["properties"] is not JsonObject { Count: > 0 }) o["additionalProperties"] = true;
                }
            }
        }

        // R4: allOf made only of primitives (for example uuid + minLength) -> one primitive schema.
        if (o["allOf"] is JsonArray prims && prims.Count > 0 && prims.All(IsPrimitive))
        {
            var merged = new JsonObject();
            foreach (var member in prims)
                foreach (var (key, value) in Resolve(member)!)
                    if (!merged.ContainsKey(key)) merged[key] = value?.DeepClone();
            o.Remove("allOf");
            foreach (var (key, value) in merged.ToList())
                if (!o.ContainsKey(key)) o[key] = value?.DeepClone();
            Bump("R4 primitive-allOf-collapsed");
        }

        // R10: a derived schema overrides an inherited property and gives it a default. Kiota assigns that default to the
        // base-typed property in the constructor, which does not compile. The default is dropped (the server applies it anyway).
        if (o["allOf"] is JsonArray inherits)
        {
            var baseProperties = new HashSet<string>(StringComparer.Ordinal);
            foreach (var member in inherits.OfType<JsonObject>().Where(m => m["$ref"] is not null))
                CollectProperties(Resolve(member), baseProperties, 0);
            var overriding = inherits.OfType<JsonObject>().Where(m => m["$ref"] is null).Select(m => m["properties"]).Append(o["properties"]).OfType<JsonObject>();
            foreach (var props in overriding)
                foreach (var (name, schema) in props.ToList())
                {
                    if (!baseProperties.Contains(name) || schema is not JsonObject s) continue;
                    var target = s["$ref"] is not null ? Resolve(s) : s;
                    if (target?.Remove("default") == true) Bump("R10 overridden-property-default-dropped");
                }
        }

        foreach (var unionKey in new[] { "oneOf", "anyOf" })
        {
            if (o[unionKey] is not JsonArray members) continue;

            // R5: nested unions (anyOf of oneOf …) -> one flat union.
            var flat = new List<JsonNode>();
            var changed = false;
            foreach (var m in members)
            {
                var r = Resolve(m);
                if (r is not null && !ReferenceEquals(r, o) && IsUnionOnly(r))
                {
                    var inner = (JsonArray)(r["oneOf"] ?? r["anyOf"])!;
                    foreach (var i in inner) flat.Add(i!.DeepClone());
                    changed = true;
                    Bump("R5 nested-union-flattened");
                }
                else flat.Add(m!.DeepClone());
            }
            if (changed) o[unionKey] = new JsonArray([.. flat]);
            var list = ((JsonArray)o[unionKey]!).ToList();

            // R6: a union of objects without "type".
            if (!o.ContainsKey("type") && list.Count > 0 && list.All(IsObjectish))
            {
                o["type"] = "object";
                Bump("R6 untyped-object-union");
            }

            // R7: inline allOf union members without "type".
            foreach (var m in list.OfType<JsonObject>())
            {
                if (m["$ref"] is null && !m.ContainsKey("type") && m["allOf"] is not null && IsObjectish(m))
                {
                    m["type"] = "object";
                    Bump("R7 untyped-union-member");
                }
            }
        }
    }

    // R8: a literal "-" path segment (wildcard) cannot become a request builder name -> path parameter with default "-".
    private void WildcardPaths()
    {
        var paths = doc["paths"]!.AsObject();
        foreach (var (path, item) in paths.ToList())
        {
            if (!path.Contains("/-/", StringComparison.Ordinal) && !path.EndsWith("/-", StringComparison.Ordinal)) continue;
            var newPath = path.Replace("/-/", "/{wildcard}/", StringComparison.Ordinal);
            if (newPath.EndsWith("/-", StringComparison.Ordinal)) newPath = newPath[..^1] + "{wildcard}";
            paths.Remove(path);
            var copy = item!.DeepClone().AsObject();
            var parameters = copy["parameters"] as JsonArray ?? [];
            parameters.Add((JsonNode)new JsonObject
            {
                ["name"] = "wildcard", ["in"] = "path", ["required"] = true,
                ["description"] = "Literal \"-\" (selects all).",
                ["schema"] = new JsonObject { ["type"] = "string", ["default"] = "-" },
            });
            copy["parameters"] = parameters;
            paths[newPath] = copy;
            Bump("R8 wildcard-path-segment");
        }
    }

    private JsonObject? Resolve(JsonNode? node)
    {
        for (var depth = 0; depth < 30; depth++)
        {
            if (node is not JsonObject o) return null;
            if (o["$ref"] is not JsonValue r || !r.TryGetValue<string>(out var reference)) return o;
            const string prefix = "#/components/schemas/";
            node = reference.StartsWith(prefix, StringComparison.Ordinal) ? _schemas[reference[prefix.Length..]] : null;
        }
        return null;
    }

    private void CollectProperties(JsonObject? schema, HashSet<string> names, int depth)
    {
        if (schema is null || depth > 20) return;
        if (schema["properties"] is JsonObject props) foreach (var (name, _) in props) names.Add(name);
        if (schema["allOf"] is JsonArray all) foreach (var m in all) CollectProperties(Resolve(m), names, depth + 1);
    }

    private static bool Has(JsonObject o, params string[] keys) => keys.Any(o.ContainsKey);

    private static bool IsUnionOnly(JsonObject? r) =>
        r is not null && Has(r, "oneOf", "anyOf") && !r.ContainsKey("properties") && !r.ContainsKey("allOf");

    private static bool IsEmptyObject(JsonObject r) =>
        (string?)r["type"] == "object" && r["properties"] is not JsonObject { Count: > 0 } && !Has(r, "allOf", "oneOf", "anyOf");

    private bool IsPrimitive(JsonNode? node) =>
        Resolve(node) is { } r && r["type"] is JsonValue t && t.TryGetValue<string>(out var type) && Primitive.Contains(type)
        && !r.ContainsKey("properties") && !Has(r, "allOf", "oneOf", "anyOf");

    private bool IsObjectish(JsonNode? node) => IsObjectish(node, 0);

    private bool IsObjectish(JsonNode? node, int depth)
    {
        if (depth > 20 || Resolve(node) is not { } r) return false;
        return (string?)r["type"] == "object" || r.ContainsKey("properties")
            || (r["allOf"] is JsonArray a && a.Any(m => IsObjectish(m, depth + 1)));
    }
}

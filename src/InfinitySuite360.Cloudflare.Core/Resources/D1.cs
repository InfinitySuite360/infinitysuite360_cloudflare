using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class D1Database : CloudflareModel
{
    public string Uuid { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Version { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public int? NumTables { get; init; }
    public long? FileSize { get; init; }
}

/// <summary>The answer to one SQL statement: rows as JSON, success flag and Cloudflare's meta data (duration, rows read/written, …).</summary>
public sealed class D1StatementResult : CloudflareModel
{
    public List<JsonElement> Results { get; init; } = [];
    public bool Success { get; init; }
    public JsonElement? Meta { get; init; }
}

/// <summary>What a SQL text does, judged locally before anything is sent. Order matters: a higher value needs more permission.</summary>
public enum D1SqlKind
{
    /// <summary>SELECT, EXPLAIN, WITH … SELECT, PRAGMA of a read-only list.</summary>
    ReadOnly = 0,
    /// <summary>INSERT, UPDATE or DELETE with WHERE, REPLACE, CREATE, other PRAGMA, anything not recognised.</summary>
    Write = 1,
    /// <summary>DROP, ALTER, DELETE or UPDATE without WHERE, VACUUM, ATTACH, TRUNCATE.</summary>
    Destructive = 2,
}

/// <summary>Local classification of SQL text (conservative: anything unknown counts as a write).</summary>
public static class D1Sql
{
    private static readonly HashSet<string> ReadPragmas = new(StringComparer.Ordinal)
    {
        "table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo", "foreign_key_list", "database_list",
        "compile_options", "function_list", "collation_list", "user_version", "schema_version", "page_count", "page_size", "encoding",
    };

    private static readonly Regex Token = new(@"[A-Za-z_][A-Za-z0-9_]*|=|\S", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// <summary>Classifies every statement; the result is the most dangerous one. Comments and string literals are ignored for the keywords.</summary>
    public static D1SqlKind Classify(string sql)
    {
        if (string.IsNullOrWhiteSpace(sql)) throw new ArgumentException("SQL is required.", nameof(sql));
        var kind = D1SqlKind.ReadOnly;
        var any = false;
        foreach (var statement in Strip(sql).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            any = true;
            var k = ClassifyStatement(Token.Matches(statement).Select(m => m.Value.ToLowerInvariant()).ToList());
            if (k > kind) kind = k;
        }
        return any ? kind : throw new ArgumentException("SQL has no statement.", nameof(sql));
    }

    private static D1SqlKind ClassifyStatement(List<string> t)
    {
        if (t.Count == 0) return D1SqlKind.ReadOnly;
        var first = t[0];
        var hasWhere = t.Contains("where");
        bool Has(params string[] words) => t.Any(x => Array.IndexOf(words, x) >= 0);
        if (Has("drop", "alter", "truncate", "vacuum", "attach", "detach")) return D1SqlKind.Destructive;
        if (first is "delete" or "update" || (first == "with" && Has("delete", "update")))
            return hasWhere ? D1SqlKind.Write : D1SqlKind.Destructive;
        switch (first)
        {
            case "select" or "explain" or "values":
                return D1SqlKind.ReadOnly;
            case "with":
                return Has("insert", "replace") ? D1SqlKind.Write : D1SqlKind.ReadOnly;
            case "pragma":
                return t.Count >= 2 && ReadPragmas.Contains(t[1]) && !t.Contains("=") ? D1SqlKind.ReadOnly : D1SqlKind.Write;
            default:
                return D1SqlKind.Write;
        }
    }

    // Replaces comments and quoted text by spaces so that keywords inside strings or comments do not count (and a ';' inside a string does not split).
    private static string Strip(string sql)
    {
        var sb = new StringBuilder(sql.Length);
        for (var i = 0; i < sql.Length; i++)
        {
            var c = sql[i];
            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-') { while (i < sql.Length && sql[i] != '\n') i++; sb.Append(' '); }
            else if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*') { var end = sql.IndexOf("*/", i + 2, StringComparison.Ordinal); i = end < 0 ? sql.Length : end + 1; sb.Append(' '); }
            else if (c is '\'' or '"' or '`')
            {
                for (i++; i < sql.Length; i++)
                {
                    if (sql[i] != c) continue;
                    if (i + 1 < sql.Length && sql[i + 1] == c) { i++; continue; }
                    break;
                }
                sb.Append(" x ");
            }
            else if (c == '[') { var end = sql.IndexOf(']', i + 1); i = end < 0 ? sql.Length : end; sb.Append(" x "); }
            else sb.Append(c);
        }
        return sb.ToString();
    }
}

/// <summary>
/// D1 databases and SQL. Queries are classified locally (<see cref="D1Sql"/>): by default only read statements are sent; writes need
/// <c>allowWriteSql</c>, DROP/ALTER/DELETE or UPDATE without WHERE need <c>allowDestructiveSql</c>. Values go in as bound parameters (<c>?</c>), never
/// concatenated into the SQL; previews show the SQL and the number of parameters, not their values. The query endpoint is a POST on the API, so the write
/// guard applies even to a SELECT: with <c>AllowWrites = false</c> nothing is sent. Deleting a database needs <c>allowDelete</c> (Time Travel can restore a
/// deleted database only within the retention period of the plan). Limits (developers.cloudflare.com/d1/platform/limits/, retrieved 17.11.2026): SQL 100 KB,
/// 100 bound parameters per query, 10 databases on Free, 1 000 000 on Paid. Export and import are not included (reachable through <c>OpenApi</c>).
/// Token permission "Account: D1: Edit" (reading "Read"). Endpoints from cloudflare/api-schemas@650bd71.
/// </summary>
public sealed class D1Client(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    private static readonly Regex NamePattern = P2.Rx(@"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$");
    private static readonly HashSet<string> LocationHints = ["wnam", "enam", "weur", "eeur", "apac", "oc"];
    private const int MaxSqlBytes = 100_000;
    private const int MaxParameters = 100;

    public Task<IReadOnlyList<D1Database>> ListDatabasesAsync(string? name = null, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<D1Database>(CloudflarePath.WithQuery(AccountPath(accountId, "d1", "database"), ("name", name)), 100, ct);

    public Task<D1Database> GetDatabaseAsync(string databaseId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<D1Database>(AccountPath(accountId, "d1", "database", databaseId), ct);

    public CloudflareChangePreview PreviewCreateDatabase(string name, string? locationHint = null, string? accountId = null) =>
        new("POST", AccountPath(accountId, "d1", "database"), CreateBody(name, locationHint), $"Create D1 database \"{name}\".");

    /// <summary>Returns the database with this name or creates it (survives a concurrent create).</summary>
    public async Task<(D1Database Database, bool Created)> EnsureDatabaseAsync(string name, string? locationHint = null, string? accountId = null, CancellationToken ct = default)
    {
        var body = CreateBody(name, locationHint);
        var path = AccountPath(accountId, "d1", "database");
        EnsureWritable(HttpMethod.Post, path);
        var existing = (await ListDatabasesAsync(name, accountId, ct).ConfigureAwait(false)).FirstOrDefault(d => d.Name == name);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<D1Database>(path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListDatabasesAsync(name, accountId, ct).ConfigureAwait(false)).FirstOrDefault(d => d.Name == name);
            if (again is null) throw;
            return (again, false);
        }
    }

    public CloudflareChangePreview PreviewRemoveDatabase(string databaseId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "d1", "database", databaseId), null, $"Delete D1 database {databaseId}. WARNING: all its tables and rows are deleted.");

    /// <summary>Deletes a database. Refused unless <paramref name="allowDelete"/> is true. False when it did not exist.</summary>
    public Task<bool> RemoveDatabaseAsync(string databaseId, bool allowDelete = false, string? accountId = null, CancellationToken ct = default)
    {
        P2.Allow(allowDelete, "deleting a database deletes all its data", nameof(allowDelete));
        return DeleteIfExistsAsync(AccountPath(accountId, "d1", "database", P1.Required(databaseId, nameof(databaseId))), null, ct);
    }

    /// <summary>The Time Travel bookmark of a point in time (now when <paramref name="timestamp"/> is null).</summary>
    public async Task<string?> GetBookmarkAsync(string databaseId, DateTimeOffset? timestamp = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "d1", "database", databaseId, "time_travel", "bookmark"), ("timestamp", timestamp?.UtcDateTime.ToString("o")));
        return P2.Str(await Api.GetAsync<JsonElement>(path, ct).ConfigureAwait(false), "bookmark");
    }

    /// <summary>Plan of a query: the SQL, its kind and the number of parameters (not their values).</summary>
    public CloudflareChangePreview PreviewQuery(string databaseId, string sql, int parameterCount = 0, bool allowWriteSql = false, bool allowDestructiveSql = false, string? accountId = null)
    {
        var kind = Check(sql, parameterCount, allowWriteSql, allowDestructiveSql);
        return new("POST", AccountPath(accountId, "d1", "database", databaseId, "query"), new JsonObject { ["sql"] = sql, ["params"] = $"[{parameterCount} bound values]" },
            $"Run {kind} SQL on database {databaseId}." + (kind == D1SqlKind.Destructive ? " WARNING: destroys or rewrites data." : ""));
    }

    /// <summary>
    /// Runs SQL with bound parameters (<c>?</c>; strings, numbers, booleans, null). Read statements by default; <paramref name="allowWriteSql"/> and
    /// <paramref name="allowDestructiveSql"/> are checked locally before anything is sent. POST is never repeated automatically.
    /// </summary>
    public async Task<IReadOnlyList<D1StatementResult>> QueryAsync(string databaseId, string sql, IReadOnlyList<object?>? parameters = null, bool allowWriteSql = false, bool allowDestructiveSql = false, string? accountId = null, CancellationToken ct = default)
    {
        Check(sql, parameters?.Count ?? 0, allowWriteSql, allowDestructiveSql);
        var body = new JsonObject { ["sql"] = sql };
        if (parameters is { Count: > 0 }) body["params"] = new JsonArray(parameters.Select(p => p is null ? null : JsonSerializer.SerializeToNode(p, p.GetType(), CloudflareJson.Options)).ToArray());
        return await Api.PostAsync<List<D1StatementResult>>(AccountPath(accountId, "d1", "database", P1.Required(databaseId, nameof(databaseId)), "query"), body, ct).ConfigureAwait(false) ?? [];
    }

    private static D1SqlKind Check(string sql, int parameterCount, bool allowWriteSql, bool allowDestructiveSql)
    {
        if (P2.Utf8(sql ?? "") > MaxSqlBytes) throw new ArgumentException("SQL may have at most 100 KB.", nameof(sql));
        if (parameterCount > MaxParameters) throw new ArgumentException("At most 100 bound parameters per query.", "parameters");
        var kind = D1Sql.Classify(sql!);
        if (kind >= D1SqlKind.Write) P2.Allow(allowWriteSql, "the SQL changes data or the schema", nameof(allowWriteSql));
        if (kind == D1SqlKind.Destructive) P2.Allow(allowDestructiveSql, "the SQL drops or alters objects, or deletes/updates without WHERE", nameof(allowDestructiveSql));
        return kind;
    }

    private static JsonObject CreateBody(string name, string? locationHint)
    {
        var body = new JsonObject { ["name"] = P2.Match(name, nameof(name), NamePattern, "letters, digits, '-' and '_', at most 63 characters") };
        if (locationHint is not null)
            body["primary_location_hint"] = LocationHints.Contains(locationHint) ? locationHint : throw new ArgumentException("Hint: wnam, enam, weur, eeur, apac or oc.", nameof(locationHint));
        return body;
    }
}

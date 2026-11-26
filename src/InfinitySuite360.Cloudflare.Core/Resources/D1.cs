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
    /// <summary>SELECT, EXPLAIN, WITH … SELECT, PRAGMA in its reading form.</summary>
    ReadOnly = 0,
    /// <summary>INSERT, UPDATE or DELETE with WHERE, REPLACE, CREATE, other PRAGMA, anything not recognised.</summary>
    Write = 1,
    /// <summary>DROP, ALTER, DELETE or UPDATE without a selective WHERE, VACUUM, ATTACH, TRUNCATE, triggers that delete or update, setting schema_version or writable_schema.</summary>
    Destructive = 2,
}

/// <summary>
/// Local classification of SQL text (conservative: anything unknown counts as a write). Since 0.7.1 (M-5): a PRAGMA counts as read-only only in its
/// reading form (no <c>=</c>, no argument for the pragmas that set a value with one, such as <c>user_version(5)</c>); setting <c>schema_version</c> or
/// <c>writable_schema</c> is destructive; DELETE or UPDATE whose WHERE clause has a part without a column (<c>WHERE 1</c>, <c>WHERE 1=1</c>, <c>WHERE ?</c>,
/// <c>… OR 'a'='a'</c>) or compares a column with itself (<c>WHERE id = id</c>) is destructive; a trigger whose body deletes, updates or drops is destructive.
/// Limit: the check is syntactic and does not evaluate expressions; read the preview.
/// </summary>
public static class D1Sql
{
    // Read without argument; with an argument or '=' they set a value.
    private static readonly HashSet<string> ReadPragmasNoArgument = new(StringComparer.Ordinal)
    {
        "database_list", "compile_options", "function_list", "collation_list", "pragma_list", "module_list", "user_version", "schema_version",
        "application_id", "page_count", "page_size", "encoding", "freelist_count", "data_version",
    };

    // Read with a table or index name as argument.
    private static readonly HashSet<string> ReadPragmasWithArgument = new(StringComparer.Ordinal)
    {
        "table_info", "table_xinfo", "table_list", "index_list", "index_info", "index_xinfo", "foreign_key_list", "foreign_key_check",
    };

    private static readonly HashSet<string> DestructivePragmas = new(StringComparer.Ordinal) { "schema_version", "writable_schema" };

    // Words that are not columns in a WHERE clause.
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "and", "or", "not", "null", "is", "in", "like", "glob", "regexp", "match", "between", "escape", "collate", "case", "when", "then", "else", "end",
        "true", "false", "exists", "cast", "as", "integer", "text", "real", "blob", "numeric", "current_date", "current_time", "current_timestamp", "isnull", "notnull",
    };

    private static readonly HashSet<string> ClauseEnd = new(StringComparer.Ordinal) { "order", "limit", "returning", "group", "having", "window", "from" };

    private static readonly Regex Token = new(@"[A-Za-z_][A-Za-z0-9_$]*|\d+(?:\.\d+)?|==|!=|<>|<=|>=|=|\S", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

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
        bool Has(params string[] words) => t.Any(x => Array.IndexOf(words, x) >= 0);
        if (Has("drop", "alter", "truncate", "vacuum", "attach", "detach")) return D1SqlKind.Destructive;
        if (first == "create" && Has("trigger") && Has("delete", "update")) return D1SqlKind.Destructive;
        if (first is "delete" or "update" || (first == "with" && Has("delete", "update")))
            return HasSelectiveWhere(t) ? D1SqlKind.Write : D1SqlKind.Destructive;
        switch (first)
        {
            case "select" or "explain" or "values":
                return D1SqlKind.ReadOnly;
            case "with":
                return Has("insert", "replace") ? D1SqlKind.Write : D1SqlKind.ReadOnly;
            case "pragma":
                return Pragma(t);
            default:
                return D1SqlKind.Write;
        }
    }

    private static D1SqlKind Pragma(List<string> t)
    {
        // PRAGMA [schema.]name [= value | (value)]
        var i = t.Count >= 4 && t[2] == "." ? 3 : 1;
        if (t.Count <= i) return D1SqlKind.Write;
        var name = t[i];
        var rest = t.Skip(i + 1).ToList();
        var setsValue = rest.Contains("=");
        var hasArgument = rest.Contains("(");
        if (!setsValue && rest.Count == 0 && (ReadPragmasNoArgument.Contains(name) || ReadPragmasWithArgument.Contains(name))) return D1SqlKind.ReadOnly;
        if (!setsValue && hasArgument && ReadPragmasWithArgument.Contains(name)) return D1SqlKind.ReadOnly;
        return DestructivePragmas.Contains(name) ? D1SqlKind.Destructive : D1SqlKind.Write;
    }

    // True when the statement has a WHERE clause and every OR-part of it names a column (and does not compare a column with itself).
    private static bool HasSelectiveWhere(List<string> t)
    {
        var where = -1;
        var depth = 0;
        for (var i = 0; i < t.Count && where < 0; i++)
        {
            if (t[i] == "(") depth++;
            else if (t[i] == ")") depth--;
            else if (depth == 0 && t[i] == "where") where = i;
        }
        if (where < 0) return false;
        var clause = new List<string>();
        depth = 0;
        for (var i = where + 1; i < t.Count; i++)
        {
            var x = t[i];
            if (x == "(") depth++;
            else if (x == ")") { if (depth == 0) break; depth--; }
            else if (depth == 0 && ClauseEnd.Contains(x)) break;
            clause.Add(x);
        }
        if (clause.Count == 0) return false;
        var parts = new List<List<string>> { new() };
        depth = 0;
        foreach (var x in clause)
        {
            if (x == "(") depth++;
            else if (x == ")") depth--;
            if (depth == 0 && x == "or") { parts.Add([]); continue; }
            parts[^1].Add(x);
        }
        return parts.All(Selective);
    }

    private static bool Selective(List<string> part)
    {
        var columns = new List<int>();
        for (var i = 0; i < part.Count; i++)
        {
            var x = part[i];
            var identifier = char.IsLetter(x[0]) || x[0] == '_';
            var function = i + 1 < part.Count && part[i + 1] == "(";
            if (identifier && !function && !Keywords.Contains(x)) columns.Add(i);
        }
        if (columns.Count == 0) return false;
        // "a = a", "a == a", "a is a": always true (apart from NULL).
        for (var i = 0; i + 2 < part.Count; i++)
            if (columns.Contains(i) && part[i + 1] is "=" or "==" or "is" && part[i + 2] == part[i]) return false;
        return true;
    }

    // Replaces comments by spaces and literals by placeholders so that keywords inside strings or comments do not count (and a ';' inside a string does not
    // split): string literals become a value (?), quoted identifiers an identifier (x).
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
                sb.Append(c == '\'' ? " ? " : " x ");
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
    private static readonly Regex NamePattern = ResourceKit.Rx(@"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$");
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
        ResourceKit.Allow(allowDelete, "deleting a database deletes all its data", nameof(allowDelete));
        return DeleteIfExistsAsync(AccountPath(accountId, "d1", "database", ResourceKit.Required(databaseId, nameof(databaseId))), null, ct);
    }

    /// <summary>The Time Travel bookmark of a point in time (now when <paramref name="timestamp"/> is null).</summary>
    public async Task<string?> GetBookmarkAsync(string databaseId, DateTimeOffset? timestamp = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "d1", "database", databaseId, "time_travel", "bookmark"), ("timestamp", timestamp?.UtcDateTime.ToString("o")));
        return ResourceKit.Str(await Api.GetAsync<JsonElement>(path, ct).ConfigureAwait(false), "bookmark");
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
        return await Api.PostAsync<List<D1StatementResult>>(AccountPath(accountId, "d1", "database", ResourceKit.Required(databaseId, nameof(databaseId)), "query"), body, ct).ConfigureAwait(false) ?? [];
    }

    private static D1SqlKind Check(string sql, int parameterCount, bool allowWriteSql, bool allowDestructiveSql)
    {
        if (ResourceKit.Utf8(sql ?? "") > MaxSqlBytes) throw new ArgumentException("SQL may have at most 100 KB.", nameof(sql));
        if (parameterCount > MaxParameters) throw new ArgumentException("At most 100 bound parameters per query.", "parameters");
        var kind = D1Sql.Classify(sql!);
        if (kind >= D1SqlKind.Write) ResourceKit.Allow(allowWriteSql, "the SQL changes data or the schema", nameof(allowWriteSql));
        if (kind == D1SqlKind.Destructive) ResourceKit.Allow(allowDestructiveSql, "the SQL drops or alters objects, or deletes/updates without WHERE", nameof(allowDestructiveSql));
        return kind;
    }

    private static JsonObject CreateBody(string name, string? locationHint)
    {
        var body = new JsonObject { ["name"] = ResourceKit.Match(name, nameof(name), NamePattern, "letters, digits, '-' and '_', at most 63 characters") };
        if (locationHint is not null)
            body["primary_location_hint"] = LocationHints.Contains(locationHint) ? locationHint : throw new ArgumentException("Hint: wnam, enam, weur, eeur, apac or oc.", nameof(locationHint));
        return body;
    }
}

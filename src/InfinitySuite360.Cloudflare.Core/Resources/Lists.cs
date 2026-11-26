using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A custom list of the account (IPs, hostnames, ASNs or redirects) that rules refer to as <c>$name</c>.</summary>
public sealed class CloudflareList : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    /// <summary>"ip", "hostname", "redirect" or "asn".</summary>
    public string Kind { get; init; } = "";
    public string? Description { get; init; }
    public int NumItems { get; init; }
    public int NumReferencingFilters { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>An entry of a list. Which of <see cref="Ip"/>, <see cref="Asn"/>, <see cref="Hostname"/> and <see cref="Redirect"/> is set depends on the list kind.</summary>
public sealed class CloudflareListItem : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>IPv4/IPv6 address or CIDR range (kind "ip").</summary>
    public string? Ip { get; init; }
    public long? Asn { get; init; }
    public JsonElement? Hostname { get; init; }
    public JsonElement? Redirect { get; init; }
    public string? Comment { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
    public DateTimeOffset? ModifiedOn { get; init; }
}

/// <summary>Input for adding an IP entry (address or CIDR range as accepted by Cloudflare).</summary>
public sealed class IpListItemInput
{
    public required string Ip { get; init; }
    public string? Comment { get; init; }
}

/// <summary>Result of an asynchronous list change (add, replace, remove).</summary>
public sealed class ListOperationResult : CloudflareModel
{
    public string OperationId { get; init; } = "";
}

/// <summary>State of an asynchronous list change.</summary>
public sealed class ListBulkOperation : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"pending", "running", "completed" or "failed".</summary>
    public string Status { get; init; } = "";
    public string? Error { get; init; }
    public DateTimeOffset? Completed { get; init; }

    public bool IsFinished => Status is "completed" or "failed";
    public bool Succeeded => Status == "completed";
}

/// <summary>
/// Custom lists of the account (<c>accounts/{id}/rules/lists</c>). A rule that refers to a list needs only one rule slot,
/// however many entries the list has; this saves the few rules of the free plan.
/// Changes to entries run asynchronously: <see cref="WaitForOperationAsync"/> waits for the result.
/// </summary>
public sealed class ListsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public const string KindIp = "ip";
    public const string KindHostname = "hostname";
    public const string KindRedirect = "redirect";
    public const string KindAsn = "asn";

    // ---- Lists ----

    public async Task<List<CloudflareList>> ListAsync(string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<CloudflareList>>(AccountPath(accountId, "rules", "lists"), ct).ConfigureAwait(false) ?? [];

    public Task<CloudflareList> GetAsync(string listId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<CloudflareList>(AccountPath(accountId, "rules", "lists", listId), ct);

    /// <summary>The list with this name, or null. List names are unique per account.</summary>
    public async Task<CloudflareList?> FindByNameAsync(string name, string? accountId = null, CancellationToken ct = default) =>
        (await ListAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(l => string.Equals(l.Name, name, StringComparison.Ordinal));

    /// <summary>Creates a list. The name has lower-case letters, digits and underscores only (it is used as <c>$name</c> in expressions).</summary>
    public Task<CloudflareList> CreateAsync(string name, string kind = KindIp, string? description = null, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<CloudflareList>(AccountPath(accountId, "rules", "lists"), new JsonObject { ["name"] = name, ["kind"] = kind, ["description"] = description }, ct);

    /// <summary>Returns the list with this name, creating it when it does not exist yet.</summary>
    public async Task<CloudflareList> EnsureAsync(string name, string kind = KindIp, string? description = null, string? accountId = null, CancellationToken ct = default) =>
        await FindByNameAsync(name, accountId, ct).ConfigureAwait(false)
        ?? await CreateAsync(name, kind, description, accountId, ct).ConfigureAwait(false);

    public Task<CloudflareList> UpdateDescriptionAsync(string listId, string description, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<CloudflareList>(AccountPath(accountId, "rules", "lists", listId), new { description }, ct);

    /// <summary>Deletes the list. Cloudflare refuses while a rule still refers to it.</summary>
    public Task DeleteAsync(string listId, string? accountId = null, CancellationToken ct = default) =>
        Api.DeleteAsync(AccountPath(accountId, "rules", "lists", listId), ct);

    // ---- Entries ----

    /// <summary>Reads all entries (cursor paging, 500 per request).</summary>
    public async Task<IReadOnlyList<CloudflareListItem>> ListItemsAsync(string listId, string? search = null, string? accountId = null, CancellationToken ct = default)
    {
        var all = new List<CloudflareListItem>();
        string? cursor = null;
        for (var guard = 0; guard < 10_000; guard++)
        {
            var path = CloudflarePath.WithQuery(AccountPath(accountId, "rules", "lists", listId, "items"),
                ("per_page", "500"), ("cursor", cursor), ("search", search));
            var response = await Api.SendAsync<List<CloudflareListItem>>(HttpMethod.Get, path, null, ct).ConfigureAwait(false);
            all.AddRange(response.Result ?? []);
            cursor = response.ResultInfo?.Cursors?.After;
            if (string.IsNullOrEmpty(cursor)) break;
        }
        return all;
    }

    public Task<CloudflareListItem> GetItemAsync(string listId, string itemId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<CloudflareListItem>(AccountPath(accountId, "rules", "lists", listId, "items", itemId), ct);

    /// <summary>Adds IP entries (appends to the existing ones). Asynchronous: wait with <see cref="WaitForOperationAsync"/>.</summary>
    public Task<ListOperationResult> AddIpItemsAsync(string listId, IEnumerable<IpListItemInput> items, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<ListOperationResult>(AccountPath(accountId, "rules", "lists", listId, "items"), IpBody(items), ct);

    /// <summary>Convenience for <see cref="AddIpItemsAsync"/> without comments.</summary>
    public Task<ListOperationResult> AddIpsAsync(string listId, IEnumerable<string> ips, string? comment = null, string? accountId = null, CancellationToken ct = default) =>
        AddIpItemsAsync(listId, ips.Select(ip => new IpListItemInput { Ip = ip, Comment = comment }), accountId, ct);

    /// <summary>Replaces all entries of the list with <paramref name="items"/>. Asynchronous.</summary>
    public Task<ListOperationResult> ReplaceIpItemsAsync(string listId, IEnumerable<IpListItemInput> items, string? accountId = null, CancellationToken ct = default) =>
        Api.PutAsync<ListOperationResult>(AccountPath(accountId, "rules", "lists", listId, "items"), IpBody(items), ct);

    /// <summary>Adds entries of any kind as raw JSON (hostnames, redirects, ASNs). Asynchronous.</summary>
    public Task<ListOperationResult> AddItemsAsync(string listId, IEnumerable<JsonElement> items, string? accountId = null, CancellationToken ct = default) =>
        Api.PostAsync<ListOperationResult>(AccountPath(accountId, "rules", "lists", listId, "items"), items.ToList(), ct);

    /// <summary>Removes entries by their IDs (see <see cref="CloudflareListItem.Id"/>). Asynchronous.</summary>
    public async Task<ListOperationResult> RemoveItemsAsync(string listId, IEnumerable<string> itemIds, string? accountId = null, CancellationToken ct = default)
    {
        var ids = itemIds.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => new { id = i }).ToList();
        if (ids.Count == 0) throw new ArgumentException("At least one entry ID is required.", nameof(itemIds));
        var response = await Api.SendAsync<ListOperationResult>(HttpMethod.Delete, AccountPath(accountId, "rules", "lists", listId, "items"), new { items = ids }, ct).ConfigureAwait(false);
        return response.Result!;
    }

    // ---- Asynchronous changes ----

    public Task<ListBulkOperation> GetOperationAsync(string operationId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<ListBulkOperation>(AccountPath(accountId, "rules", "lists", "bulk_operations", operationId), ct);

    /// <summary>
    /// Polls the operation until it is completed or failed. Throws <see cref="TimeoutException"/> when it is still running after
    /// <paramref name="timeout"/> (default 60 seconds) and <see cref="InvalidOperationException"/> when it failed.
    /// </summary>
    public async Task<ListBulkOperation> WaitForOperationAsync(string operationId, TimeSpan? timeout = null, TimeSpan? pollInterval = null, string? accountId = null, CancellationToken ct = default)
    {
        var deadline = DateTimeOffset.UtcNow + (timeout ?? TimeSpan.FromSeconds(60));
        var interval = pollInterval ?? TimeSpan.FromSeconds(1);
        while (true)
        {
            var op = await GetOperationAsync(operationId, accountId, ct).ConfigureAwait(false);
            if (op.Succeeded) return op;
            if (op.Status == "failed")
                throw new InvalidOperationException($"Cloudflare list operation {operationId} failed: {op.Error ?? "no reason given"}");
            if (DateTimeOffset.UtcNow >= deadline)
                throw new TimeoutException($"Cloudflare list operation {operationId} is still {op.Status} after the timeout.");
            await Task.Delay(interval, ct).ConfigureAwait(false);
        }
    }

    private static List<object> IpBody(IEnumerable<IpListItemInput> items)
    {
        var list = items.Select(i => (object)new { ip = i.Ip, comment = i.Comment }).ToList();
        if (list.Count == 0) throw new ArgumentException("At least one entry is required.", nameof(items));
        return list;
    }
}

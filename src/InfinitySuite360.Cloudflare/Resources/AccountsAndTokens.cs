using System.Text.Json;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

public sealed class Account : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Type { get; init; }
    public DateTimeOffset? CreatedOn { get; init; }
}

public sealed class TokenVerification : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"active", "disabled" or "expired".</summary>
    public string Status { get; init; } = "";
    public DateTimeOffset? ExpiresOn { get; init; }
    public DateTimeOffset? NotBefore { get; init; }
    public bool IsActive => string.Equals(Status, "active", StringComparison.OrdinalIgnoreCase);
}

public sealed class ApiTokenDetails : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Status { get; init; } = "";
    public DateTimeOffset? ExpiresOn { get; init; }
    public DateTimeOffset? IssuedOn { get; init; }
    public DateTimeOffset? LastUsedOn { get; init; }
    public List<JsonElement> Policies { get; init; } = [];
}

/// <summary>Accounts and API tokens.</summary>
public sealed class AccountsClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    public Task<IReadOnlyList<Account>> ListAsync(CancellationToken ct = default) =>
        Api.ListAllToListAsync<Account>("accounts", 50, ct);

    public Task<Account> GetAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<Account>(AccountPath(accountId), ct);

    /// <summary>Verifies the configured user token (GET /user/tokens/verify).</summary>
    public Task<TokenVerification> VerifyUserTokenAsync(CancellationToken ct = default) =>
        Api.GetAsync<TokenVerification>("user/tokens/verify", ct);

    /// <summary>Verifies an account-owned token (GET /accounts/{id}/tokens/verify).</summary>
    public Task<TokenVerification> VerifyAccountTokenAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<TokenVerification>(AccountPath(accountId, "tokens", "verify"), ct);

    /// <summary>
    /// Verifies the token as a user token first and, if that fails, as an account token (when an account is configured).
    /// </summary>
    public async Task<TokenVerification> VerifyAsync(CancellationToken ct = default)
    {
        try { return await VerifyUserTokenAsync(ct).ConfigureAwait(false); }
        catch (CloudflareApiException) when (!string.IsNullOrWhiteSpace(Api.Options.AccountId))
        {
            return await VerifyAccountTokenAsync(null, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Details of a user token including its policies (requires "API Tokens: Read").</summary>
    public Task<ApiTokenDetails> GetUserTokenAsync(string tokenId, CancellationToken ct = default) =>
        Api.GetAsync<ApiTokenDetails>(CloudflarePath.Of("user", "tokens", tokenId), ct);

    /// <summary>Permission groups available for tokens.</summary>
    public Task<List<JsonElement>> ListPermissionGroupsAsync(CancellationToken ct = default) =>
        Api.GetAsync<List<JsonElement>>("user/tokens/permission_groups", ct);
}

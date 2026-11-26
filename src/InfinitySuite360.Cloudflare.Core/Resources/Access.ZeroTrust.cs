using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A new or changed Access group (include, exclude, require rules; see <see cref="AccessRules"/>).</summary>
public sealed class AccessGroupInput
{
    public required string Name { get; init; }
    public required List<JsonElement> Include { get; init; }
    public List<JsonElement>? Exclude { get; init; }
    public List<JsonElement>? Require { get; init; }
}

/// <summary>Result of issuing or rotating a service token: the token and its client secret (shown by Cloudflare only once).</summary>
public sealed class IssuedServiceToken
{
    internal IssuedServiceToken(AccessServiceToken token, CloudflareOneTimeSecret secret)
    {
        Token = token;
        ClientSecret = secret;
    }

    public AccessServiceToken Token { get; }
    /// <summary>Header <c>CF-Access-Client-Id</c> (not secret).</summary>
    public string ClientId => Token.ClientId;
    /// <summary>Header <c>CF-Access-Client-Secret</c>; <see cref="CloudflareOneTimeSecret.TakeValue"/> hands it over once.</summary>
    public CloudflareOneTimeSecret ClientSecret { get; }

    public override string ToString() => $"IssuedServiceToken({Token.Id}, \"{Token.Name}\", client secret {P1.Redacted})";
}

/// <summary>State of an Access policy test (<c>access/policy-tests</c>): how many users the tested policies would let in.</summary>
public sealed class AccessPolicyTest : CloudflareModel
{
    public string Id { get; init; } = "";
    /// <summary>"processing", "complete", "blocked", "exceeded time" (or "success" right after the start).</summary>
    public string Status { get; init; } = "";
    public int? TotalUsers { get; init; }
    public int? UsersApproved { get; init; }
    public int? UsersBlocked { get; init; }
    public int? UsersErrored { get; init; }
    public int? PercentApproved { get; init; }
    public int? PercentBlocked { get; init; }
    public int? PercentErrored { get; init; }
    public int? PercentUsersProcessed { get; init; }
}

/// <summary>One user of a policy test result.</summary>
public sealed class AccessPolicyTestUser : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? Email { get; init; }
    /// <summary>"approved", "blocked" or "error".</summary>
    public string Status { get; init; } = "";
}

/// <summary>An mTLS root certificate of Access (the public CA certificate; Cloudflare never holds a private key for it).</summary>
public sealed class AccessCertificate : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string? Fingerprint { get; init; }
    public DateTimeOffset? ExpiresOn { get; init; }
    public List<string> AssociatedHostnames { get; init; } = [];
    public DateTimeOffset? CreatedAt { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

/// <summary>Per-hostname mTLS settings (client certificate forwarding to the origin, China network).</summary>
public sealed class AccessCertificateHostnameSetting : CloudflareModel
{
    public string Hostname { get; init; } = "";
    public bool ChinaNetwork { get; init; }
    public bool ClientCertificateForwarding { get; init; }
}

/// <summary>The Zero Trust organization: team domain, login page, session lengths and account-wide Access switches.</summary>
public sealed class AccessOrganization : CloudflareModel
{
    public string? Name { get; init; }
    /// <summary>The team domain, for example "team.cloudflareaccess.com" (issuer of the Access JWT).</summary>
    public string? AuthDomain { get; init; }
    public string? SessionDuration { get; init; }
    public bool? AutoRedirectToIdentity { get; init; }
    public bool? IsUiReadOnly { get; init; }
    public bool? AllowAuthenticateViaWarp { get; init; }
    public string? WarpAuthSessionDuration { get; init; }
    /// <summary>Deny every request to hostnames of the account that have no Access application (default action "deny").</summary>
    public bool? DenyUnmatchedRequests { get; init; }
    public bool? MfaRequiredForAllApps { get; init; }
    public JsonElement? LoginDesign { get; init; }
    public JsonElement? CustomPages { get; init; }
}

/// <summary>A change of the organization; only set fields are sent (PATCH).</summary>
public sealed class AccessOrganizationChange
{
    public string? Name { get; init; }
    /// <summary>Changing the team domain changes the issuer of every Access JWT and the login address; needs <c>allowDisconnect</c>.</summary>
    public string? AuthDomain { get; init; }
    public string? SessionDuration { get; init; }
    public bool? AutoRedirectToIdentity { get; init; }
    public bool? IsUiReadOnly { get; init; }
    public string? UiReadOnlyToggleReason { get; init; }
    public bool? AllowAuthenticateViaWarp { get; init; }
    public string? WarpAuthSessionDuration { get; init; }
    /// <summary>True tightens the default action to "deny" (needs <c>allowBlock</c>), false loosens it (needs <c>allowLoosen</c>).</summary>
    public bool? DenyUnmatchedRequests { get; init; }
    /// <summary>True can lock out users without a second factor (needs <c>allowBlock</c>), false loosens (needs <c>allowLoosen</c>).</summary>
    public bool? MfaRequiredForAllApps { get; init; }
    public JsonObject? LoginDesign { get; init; }
}

/// <summary>A Zero Trust user (seat). Read-only; contains personal data, so do not copy it into logs.</summary>
public sealed class AccessUser : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? Email { get; init; }
    public bool? AccessSeat { get; init; }
    public bool? GatewaySeat { get; init; }
    public double? ActiveDeviceCount { get; init; }
    public DateTimeOffset? LastSuccessfulLogin { get; init; }
}

/// <summary>An active Access session of a user (application names and expiry; no session token).</summary>
public sealed class AccessActiveSession : CloudflareModel
{
    public string? Name { get; init; }
    /// <summary>Unix time of expiry.</summary>
    public long? Expiration { get; init; }
    public JsonElement? Metadata { get; init; }
}

/// <summary>How permissive an Access policy is; used by the loosening and lock-out checks.</summary>
internal static class AccessPolicyRisk
{
    private static readonly string[] Decisions = ["deny", "allow", "non_identity", "bypass"];

    public static int Rank(string decision) => Array.IndexOf(Decisions, decision);

    public static bool Has(IEnumerable<JsonElement> rules, string name) =>
        rules.Any(r => r.ValueKind == JsonValueKind.Object && r.TryGetProperty(name, out _));

    public static bool Admits(string decision) => decision is "allow" or "non_identity" or "bypass";

    /// <summary>The policy lets everybody in: bypass, or allow/non_identity for "everyone" without a require rule.</summary>
    public static bool AdmitsEveryone(string decision, IReadOnlyList<JsonElement> include, IReadOnlyList<JsonElement> require) =>
        decision == "bypass" || (Admits(decision) && Has(include, "everyone") && require.Count == 0);

    public static bool DeniesEveryone(string decision, IReadOnlyList<JsonElement> include) => decision == "deny" && Has(include, "everyone");

    private static bool Same(JsonElement a, JsonElement b) => JsonNode.DeepEquals(JsonNode.Parse(a.GetRawText()), JsonNode.Parse(b.GetRawText()));

    private static bool Removed(IReadOnlyList<JsonElement> before, IReadOnlyList<JsonElement> after) => before.Any(b => !after.Any(a => Same(a, b)));

    /// <summary>Why <paramref name="next"/> is looser than <paramref name="current"/>, or null.</summary>
    public static string? Loosening((string Decision, IReadOnlyList<JsonElement> Include, IReadOnlyList<JsonElement> Exclude, IReadOnlyList<JsonElement> Require) current,
        (string Decision, IReadOnlyList<JsonElement> Include, IReadOnlyList<JsonElement> Exclude, IReadOnlyList<JsonElement> Require) next)
    {
        if (Rank(next.Decision) > Rank(current.Decision)) return $"decision {current.Decision} → {next.Decision}";
        if (AdmitsEveryone(next.Decision, next.Include, next.Require) && !AdmitsEveryone(current.Decision, current.Include, current.Require)) return "it would admit everyone";
        if (current.Decision == "deny")
            return Removed(current.Include, next.Include) ? "a deny policy would match fewer requests" : null;
        if (Removed(current.Require, next.Require)) return "require rules would be removed";
        if (Removed(current.Exclude, next.Exclude)) return "exclude rules would be removed";
        return null;
    }

    public static (string Decision, IReadOnlyList<JsonElement> Include, IReadOnlyList<JsonElement> Exclude, IReadOnlyList<JsonElement> Require) Of(AccessPolicy p) =>
        (p.Decision, p.Include, p.Exclude, p.Require);

    public static (string Decision, IReadOnlyList<JsonElement> Include, IReadOnlyList<JsonElement> Exclude, IReadOnlyList<JsonElement> Require) Of(AccessPolicyInput p) =>
        (p.Decision, p.Include, p.Exclude ?? [], p.Require ?? []);
}

public sealed partial class AccessClient
{
    private static readonly HashSet<string> AppTypes = ["self_hosted", "saas", "ssh", "vnc", "app_launcher", "warp", "biso", "bookmark", "dash_sso", "infrastructure", "rdp", "mcp", "mcp_portal", "proxy_endpoint"];
    private static readonly HashSet<string> IdpTypes = ["onetimepin", "azureAD", "saml", "centrify", "facebook", "github", "google-apps", "google", "linkedin", "oidc", "duo", "okta", "onelogin", "pingone", "yandex", "cloudflare", "passkeys"];

    // ------------------------------------------------------------------ applications

    /// <summary>Plan of a new application (sends nothing).</summary>
    public CloudflareChangePreview PreviewEnsureApplication(AccessApplicationInput app, bool allowNoPolicy = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "apps"), ZT.Redact(AppBody(app, allowNoPolicy)),
            $"Create Access application \"{app.Name}\" for {app.Domain} ({app.Type}) with {ZT.Plural(app.Policies?.Count ?? 0, "policy", "policies")}. "
            + "WARNING: from then on the hostname needs an Access login.");

    /// <summary>
    /// Returns the application for this domain and type or creates it; an existing application is not changed. An application without policies denies
    /// everyone (Cloudflare's default), so that needs <paramref name="allowNoPolicy"/>. Creating protects a hostname that may be public today: check the
    /// preview first.
    /// </summary>
    public async Task<(AccessApplication Application, bool Created)> EnsureApplicationAsync(AccessApplicationInput app, bool allowNoPolicy = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var body = AppBody(app, allowNoPolicy);
        var path = AccountPath(accountId, "access", "apps");
        EnsureWritable(HttpMethod.Post, path);
        var existing = await FindApplicationAsync(app, accountId, ct).ConfigureAwait(false);
        if (existing is not null) return (existing, false);
        try { return (await ZT.SendAsync<AccessApplication>(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = await FindApplicationAsync(app, accountId, ct).ConfigureAwait(false);
            return again is null ? throw ZT.Conflict("POST", path, $"Application for {app.Domain} is reported as existing but was not found.") : (again, false);
        }
    }

    public CloudflareChangePreview PreviewRemoveApplication(string appId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "access", "apps", appId), null,
            $"Delete Access application {appId}. WARNING: its hostname is no longer protected by an Access login.");

    /// <summary>Deletes an application. This always loosens (the hostname loses its login), so it needs <paramref name="allowUnprotect"/>. False when it did not exist.</summary>
    public Task<bool> RemoveApplicationAsync(string appId, bool allowUnprotect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps", P1.Required(appId, nameof(appId)));
        EnsureWritable(HttpMethod.Delete, path);
        P2.Allow(allowUnprotect, "deleting an Access application removes the login protection of its hostname", nameof(allowUnprotect));
        return DeleteIfExistsAsync(path, null, ct);
    }

    public CloudflareChangePreview PreviewRevokeApplicationTokens(string appId, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "apps", appId, "revoke_tokens"), null,
            $"Revoke every Access token of application {appId}: all users must log in again.");

    /// <summary>Logs every user of the application out (POST, not retried). Needs <paramref name="allowDisconnect"/>.</summary>
    public async Task RevokeApplicationTokensAsync(string appId, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps", P1.Required(appId, nameof(appId)), "revoke_tokens");
        EnsureWritable(HttpMethod.Post, path);
        P2.Allow(allowDisconnect, "revoking the tokens of an application logs every user out at once", nameof(allowDisconnect));
        await Api.SendAsync<JsonElement>(HttpMethod.Post, path, null, ct).ConfigureAwait(false);
    }

    private async Task<AccessApplication?> FindApplicationAsync(AccessApplicationInput app, string? accountId, CancellationToken ct) =>
        (await ListApplicationsAsync(accountId, ct).ConfigureAwait(false))
        .FirstOrDefault(a => string.Equals(a.Domain, app.Domain.Trim(), StringComparison.OrdinalIgnoreCase) && a.Type == app.Type);

    private static JsonObject AppBody(AccessApplicationInput app, bool allowNoPolicy)
    {
        P1.Required(app.Name, nameof(app), 350);
        var domain = P1.Required(app.Domain, nameof(app)).Trim();
        if (domain.Contains("://", StringComparison.Ordinal)) throw new ArgumentException("Domain without scheme, for example app.example.com/admin.", nameof(app));
        if (!AppTypes.Contains(app.Type)) throw new ArgumentException($"Unknown application type \"{app.Type}\".", nameof(app));
        if (app.Policies is not { Count: > 0 })
            P2.Allow(allowNoPolicy, "an Access application without policies denies everyone", nameof(allowNoPolicy));
        var body = new JsonObject { ["name"] = app.Name, ["domain"] = domain, ["type"] = app.Type, ["session_duration"] = app.SessionDuration };
        if (app.AppLauncherVisible is { } v) body["app_launcher_visible"] = v;
        if (app.AutoRedirectToIdentity is { } r) body["auto_redirect_to_identity"] = r;
        if (app.AllowedIdps is { Count: > 0 } idps) body["allowed_idps"] = P1.Arr(idps);
        if (app.Policies is { Count: > 0 } policies) body["policies"] = new JsonArray(policies.Select(ZT.ToNode).ToArray());
        return body;
    }

    // ------------------------------------------------------------------ application policies

    public CloudflareChangePreview PreviewAddApplicationPolicy(string appId, AccessPolicyInput policy, bool allowLoosen = false, bool allowBlock = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "apps", appId, "policies"), PolicyBody(policy, allowLoosen, allowBlock, null), Describe("Add policy", policy));

    /// <summary>
    /// Adds a policy to an application (POST, not retried after a server error). A policy that admits everyone (bypass, or allow/non_identity for
    /// "everyone" without a require rule) needs <paramref name="allowLoosen"/>; a deny for everyone needs <paramref name="allowBlock"/>.
    /// </summary>
    public Task<AccessPolicy> AddApplicationPolicyAsync(string appId, AccessPolicyInput policy, bool allowLoosen = false, bool allowBlock = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps", P1.Required(appId, nameof(appId)), "policies");
        EnsureWritable(HttpMethod.Post, path);
        return Api.PostAsync<AccessPolicy>(path, PolicyBody(policy, allowLoosen, allowBlock, null), ct);
    }

    /// <summary>Plan of a policy change: reads the current policy and names the loosening, if any (sends no write).</summary>
    public async Task<CloudflareChangePreview> PreviewChangeApplicationPolicyAsync(string appId, string policyId, AccessPolicyInput policy, string? accountId = null, CancellationToken ct = default)
    {
        var current = await Api.GetAsync<AccessPolicy>(AccountPath(accountId, "access", "apps", appId, "policies", policyId), ct).ConfigureAwait(false);
        var loosening = AccessPolicyRisk.Loosening(AccessPolicyRisk.Of(current), AccessPolicyRisk.Of(policy));
        return new("PUT", AccountPath(accountId, "access", "apps", appId, "policies", policyId), PolicyBody(policy, true, true, null),
            Describe($"Change policy \"{current.Name}\" of application {appId} to", policy) + (loosening is null ? "" : $" WARNING: loosens ({loosening})."));
    }

    /// <summary>
    /// Replaces an application policy after a fresh read. Loosening (more permissive decision, admitting everyone, removing require/exclude rules,
    /// a deny that matches fewer requests) needs <paramref name="allowLoosen"/>; a deny for everyone needs <paramref name="allowBlock"/>. Written only on change.
    /// </summary>
    public async Task<(AccessPolicy Policy, bool Changed)> ChangeApplicationPolicyAsync(string appId, string policyId, AccessPolicyInput policy, bool allowLoosen = false, bool allowBlock = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps", P1.Required(appId, nameof(appId)), "policies", P1.Required(policyId, nameof(policyId)));
        EnsureWritable(HttpMethod.Put, path);
        var currentRaw = await P2.ResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        var current = P1.As<AccessPolicy>(currentRaw);
        var body = PolicyBody(policy, allowLoosen, allowBlock, current);
        if (P1.Covers(P1.Node(currentRaw), body)) return (current, false);
        return (await Api.PutAsync<AccessPolicy>(path, body, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewRemoveApplicationPolicy(string appId, string policyId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "access", "apps", appId, "policies", policyId), null,
            $"Remove policy {policyId} from application {appId} (refused when it is the last policy that admits anyone).");

    /// <summary>
    /// Removes a policy from an application after a fresh read of the application's policies. Removing the last policy, or the last one that admits
    /// anyone, locks everybody out and needs <paramref name="allowRemoveLast"/>; removing a deny policy loosens and needs <paramref name="allowLoosen"/>.
    /// False when the application or the policy does not exist.
    /// </summary>
    public async Task<bool> RemoveApplicationPolicyAsync(string appId, string policyId, bool allowRemoveLast = false, bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps", P1.Required(appId, nameof(appId)), "policies", P1.Required(policyId, nameof(policyId)));
        EnsureWritable(HttpMethod.Delete, path);
        List<AccessPolicy> policies;
        try { policies = await ListApplicationPoliciesAsync(appId, accountId, ct).ConfigureAwait(false) ?? []; }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return false; }
        var target = policies.FirstOrDefault(p => p.Id == policyId);
        if (target is null) return false;
        var rest = policies.Where(p => p.Id != policyId).ToList();
        if (rest.Count == 0) P2.Allow(allowRemoveLast, $"policy \"{target.Name}\" is the last policy of application {appId}; without it nobody gets in", nameof(allowRemoveLast));
        else if (AccessPolicyRisk.Admits(target.Decision) && !rest.Any(p => AccessPolicyRisk.Admits(p.Decision)))
            P2.Allow(allowRemoveLast, $"policy \"{target.Name}\" is the last policy of application {appId} that admits anyone", nameof(allowRemoveLast));
        if (target.Decision == "deny") P2.Allow(allowLoosen, $"removing deny policy \"{target.Name}\" loosens application {appId}", nameof(allowLoosen));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ reusable policies

    public Task<AccessPolicy> GetPolicyAsync(string policyId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<AccessPolicy>(AccountPath(accountId, "access", "policies", policyId), ct);

    public CloudflareChangePreview PreviewEnsurePolicy(AccessPolicyInput policy, bool allowLoosen = false, bool allowBlock = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "policies"), PolicyBody(policy, allowLoosen, allowBlock, null), Describe("Create reusable policy", policy));

    /// <summary>Returns the reusable policy with this name or creates it (same checks as <see cref="AddApplicationPolicyAsync"/>); an existing policy is not changed.</summary>
    public async Task<(AccessPolicy Policy, bool Created)> EnsurePolicyAsync(AccessPolicyInput policy, bool allowLoosen = false, bool allowBlock = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "policies");
        EnsureWritable(HttpMethod.Post, path);
        var body = PolicyBody(policy, allowLoosen, allowBlock, null);
        var existing = (await ListPoliciesAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(p => p.Name == policy.Name);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<AccessPolicy>(path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListPoliciesAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(p => p.Name == policy.Name);
            return again is null ? throw ZT.Conflict("POST", path, $"Policy \"{policy.Name}\" is reported as existing but was not found.") : (again, false);
        }
    }

    /// <summary>Replaces a reusable policy after a fresh read (same checks as <see cref="ChangeApplicationPolicyAsync"/>). It applies to every application that uses it.</summary>
    public async Task<(AccessPolicy Policy, bool Changed)> ChangePolicyAsync(string policyId, AccessPolicyInput policy, bool allowLoosen = false, bool allowBlock = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "policies", P1.Required(policyId, nameof(policyId)));
        EnsureWritable(HttpMethod.Put, path);
        var currentRaw = await P2.ResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        var current = P1.As<AccessPolicy>(currentRaw);
        var body = PolicyBody(policy, allowLoosen, allowBlock, current);
        if (P1.Covers(P1.Node(currentRaw), body)) return (current, false);
        return (await Api.PutAsync<AccessPolicy>(path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>
    /// Deletes a reusable policy after reading it and the applications: when an application would be left without a policy (or without one that admits
    /// anyone) this needs <paramref name="allowRemoveLast"/>; a deny policy needs <paramref name="allowLoosen"/>. If the applications cannot be read the call
    /// fails (fail-closed). False when the policy did not exist.
    /// </summary>
    public async Task<bool> RemovePolicyAsync(string policyId, bool allowRemoveLast = false, bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "policies", P1.Required(policyId, nameof(policyId)));
        EnsureWritable(HttpMethod.Delete, path);
        AccessPolicy target;
        try { target = await GetPolicyAsync(policyId, accountId, ct).ConfigureAwait(false); }
        catch (CloudflareApiException ex) when (ex.StatusCode == HttpStatusCode.NotFound) { return false; }
        var apps = await ListApplicationsAsync(accountId, ct).ConfigureAwait(false);
        foreach (var app in apps)
        {
            var ids = app.Policies.Select(PolicyId).ToList();
            if (!ids.Contains(policyId)) continue;
            var rest = app.Policies.Where(p => PolicyId(p) != policyId).ToList();
            if (rest.Count == 0 || (AccessPolicyRisk.Admits(target.Decision) && !rest.Any(p => AccessPolicyRisk.Admits(P2.Str(p, "decision") ?? ""))))
                P2.Allow(allowRemoveLast, $"policy \"{target.Name}\" is the last policy that admits anyone to application {app.Name}", nameof(allowRemoveLast));
        }
        if (target.Decision == "deny") P2.Allow(allowLoosen, $"removing deny policy \"{target.Name}\" loosens every application that uses it", nameof(allowLoosen));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    private static string? PolicyId(JsonElement p) => p.ValueKind == JsonValueKind.String ? p.GetString() : P2.Str(p, "id");

    // ------------------------------------------------------------------ policy tests (POST that only reads)

    public CloudflareChangePreview PreviewStartPolicyTest(IEnumerable<string> policyIds, string? accountId = null)
    {
        var ids = policyIds.Select(id => P1.Required(id, nameof(policyIds))).ToList();
        return new("POST", AccountPath(accountId, "access", "policy-tests"), new JsonObject { ["policies"] = P1.Arr(ids) },
            $"Start an Access policy test over {ZT.Plural(ids.Count, "policy", "policies")} (reads only, but is a POST).");
    }

    /// <summary>
    /// Starts a policy test: Cloudflare evaluates the policies against the users of the organization and changes nothing. The endpoint is a POST, so the
    /// write guard (<c>AllowWrites</c>, <c>WriteFilter</c>) applies and it is not retried after a server error. Poll with <see cref="GetPolicyTestAsync"/>.
    /// </summary>
    public Task<AccessPolicyTest> StartPolicyTestAsync(IEnumerable<string> policyIds, string? accountId = null, CancellationToken ct = default)
    {
        var preview = PreviewStartPolicyTest(policyIds, accountId);
        if (((JsonObject)preview.Body!)["policies"]!.AsArray().Count == 0) throw new ArgumentException("At least one policy id.", nameof(policyIds));
        return Api.PostAsync<AccessPolicyTest>(preview.Path, preview.Body, ct);
    }

    public Task<AccessPolicyTest> GetPolicyTestAsync(string testId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<AccessPolicyTest>(AccountPath(accountId, "access", "policy-tests", P1.Required(testId, nameof(testId))), ct);

    /// <summary>Users of a test result, optionally only "approved", "blocked" or "error" (personal data: do not log).</summary>
    public Task<IReadOnlyList<AccessPolicyTestUser>> ListPolicyTestUsersAsync(string testId, string? status = null, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessPolicyTestUser>(CloudflarePath.WithQuery(AccountPath(accountId, "access", "policy-tests", P1.Required(testId, nameof(testId)), "users"), ("status", status)), 50, ct);

    // ------------------------------------------------------------------ groups

    public CloudflareChangePreview PreviewEnsureGroup(AccessGroupInput group, bool allowLoosen = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "groups"), GroupBody(group, allowLoosen, null),
            $"Create Access group \"{group.Name}\" ({group.Include.Count} include, {group.Exclude?.Count ?? 0} exclude, {group.Require?.Count ?? 0} require rule(s)).");

    /// <summary>Returns the group with this name or creates it. A group that includes everyone needs <paramref name="allowLoosen"/>; an existing group is not changed.</summary>
    public async Task<(AccessGroup Group, bool Created)> EnsureGroupAsync(AccessGroupInput group, bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "groups");
        EnsureWritable(HttpMethod.Post, path);
        var body = GroupBody(group, allowLoosen, null);
        var existing = (await ListGroupsAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(g => g.Name == group.Name);
        if (existing is not null) return (existing, false);
        try { return (await Api.PostAsync<AccessGroup>(path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListGroupsAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(g => g.Name == group.Name);
            return again is null ? throw ZT.Conflict("POST", path, $"Group \"{group.Name}\" is reported as existing but was not found.") : (again, false);
        }
    }

    /// <summary>Replaces a group after a fresh read. Including everyone or removing exclude/require rules loosens every policy that uses it and needs <paramref name="allowLoosen"/>.</summary>
    public async Task<(AccessGroup Group, bool Changed)> ChangeGroupAsync(string groupId, AccessGroupInput group, bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "groups", P1.Required(groupId, nameof(groupId)));
        EnsureWritable(HttpMethod.Put, path);
        var currentRaw = await P2.ResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        var current = P1.As<AccessGroup>(currentRaw);
        var body = GroupBody(group, allowLoosen, current);
        if (P1.Covers(P1.Node(currentRaw), body)) return (current, false);
        return (await Api.PutAsync<AccessGroup>(path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>
    /// Deletes a group. When reusable policies, application policies or other groups refer to it, this needs <paramref name="allowInUse"/> (the check reads
    /// policies, applications and groups; if they cannot be read the call fails). False when it did not exist.
    /// </summary>
    public async Task<bool> RemoveGroupAsync(string groupId, bool allowInUse = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "groups", P1.Required(groupId, nameof(groupId)));
        EnsureWritable(HttpMethod.Delete, path);
        if (!allowInUse)
        {
            var users = new List<string>();
            foreach (var p in await ListPoliciesAsync(accountId, ct).ConfigureAwait(false))
                if (ZT.References(ToElement(new { p.Include, p.Exclude, p.Require }), "group", "id", groupId)) users.Add($"policy \"{p.Name}\"");
            foreach (var a in await ListApplicationsAsync(accountId, ct).ConfigureAwait(false))
                if (a.Policies.Any(x => ZT.References(x, "group", "id", groupId))) users.Add($"application \"{a.Name}\"");
            foreach (var g in await ListGroupsAsync(accountId, ct).ConfigureAwait(false))
                if (g.Id != groupId && ZT.References(ToElement(new { g.Include, g.Exclude, g.Require }), "group", "id", groupId)) users.Add($"group \"{g.Name}\"");
            if (users.Count > 0)
                throw new InvalidOperationException($"Refused: group {groupId} is used by {string.Join(", ", users)}. Remove the references first or pass allowInUse: true deliberately.");
        }
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ service tokens

    public CloudflareChangePreview PreviewIssueServiceToken(string name, string duration = "8760h", bool allowNoExpiry = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "service_tokens"), ServiceTokenBody(name, duration, allowNoExpiry),
            $"Create service token \"{name}\" valid for {duration}. The client secret is shown once in the result.");

    /// <summary>
    /// Creates a service token (POST, never retried after a server error: a retry could create a second token). The client secret is moved into
    /// <see cref="IssuedServiceToken.ClientSecret"/> before any model is built. "forever" needs <paramref name="allowNoExpiry"/>.
    /// </summary>
    public async Task<IssuedServiceToken> IssueServiceTokenAsync(string name, string duration = "8760h", bool allowNoExpiry = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "service_tokens");
        var body = ServiceTokenBody(name, duration, allowNoExpiry);
        return Issued(await P2.ResultAsync(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false), "POST", path);
    }

    public CloudflareChangePreview PreviewRotateServiceTokenSecret(string tokenId, TimeSpan? previousSecretGrace = null, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "service_tokens", tokenId, "rotate"), RotateBody(previousSecretGrace),
            previousSecretGrace is { } g
                ? $"Rotate the secret of service token {tokenId}; the old secret keeps working for {g.TotalHours:0.#} h."
                : $"Rotate the secret of service token {tokenId}. WARNING: the old secret stops working at once.");

    /// <summary>
    /// Issues a new client secret. Without <paramref name="previousSecretGrace"/> the old secret stops working at once and every machine using it is cut
    /// off, so that needs <paramref name="allowDisconnect"/>. The new secret is only in the result.
    /// </summary>
    public async Task<IssuedServiceToken> RotateServiceTokenSecretAsync(string tokenId, TimeSpan? previousSecretGrace = null, bool allowDisconnect = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "service_tokens", P1.Required(tokenId, nameof(tokenId)), "rotate");
        EnsureWritable(HttpMethod.Post, path);
        if (previousSecretGrace is { } g && (g <= TimeSpan.Zero || g > TimeSpan.FromDays(30))) throw new ArgumentOutOfRangeException(nameof(previousSecretGrace), "Grace period above zero and at most 30 days.");
        if (previousSecretGrace is null)
            P2.Allow(allowDisconnect, "rotating without a grace period invalidates the old secret at once", nameof(allowDisconnect));
        return Issued(await P2.ResultAsync(Api, HttpMethod.Post, path, RotateBody(previousSecretGrace), ct).ConfigureAwait(false), "POST", path);
    }

    public CloudflareChangePreview PreviewRemoveServiceToken(string tokenId, string? accountId = null) =>
        new("DELETE", AccountPath(accountId, "access", "service_tokens", tokenId), null,
            $"Delete service token {tokenId}. WARNING: every machine using it is refused at once.");

    /// <summary>
    /// Deletes a service token after a fresh read: a token that was ever used (<c>last_seen_at</c> set) or is referenced by a policy cuts machines off and
    /// needs <paramref name="allowDisconnect"/>. False when it did not exist.
    /// </summary>
    public async Task<bool> RemoveServiceTokenAsync(string tokenId, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "service_tokens", P1.Required(tokenId, nameof(tokenId)));
        EnsureWritable(HttpMethod.Delete, path);
        var token = await ZT.GetOrNullAsync<AccessServiceToken>(Api, path, ct).ConfigureAwait(false);
        if (token is null) return false;
        if (!allowDisconnect)
        {
            if (token.LastSeenAt is not null)
                throw new InvalidOperationException($"Refused: service token \"{token.Name}\" was used (last seen {token.LastSeenAt:yyyy-MM-dd}); deleting it cuts those machines off. Pass allowDisconnect: true deliberately.");
            var used = (await ListPoliciesAsync(accountId, ct).ConfigureAwait(false))
                .Where(p => ZT.References(ToElement(new { p.Include, p.Require }), "service_token", "token_id", tokenId)).Select(p => p.Name).ToList();
            if (used.Count > 0)
                throw new InvalidOperationException($"Refused: service token \"{token.Name}\" is used by {string.Join(", ", used)}. Pass allowDisconnect: true deliberately.");
        }
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    private static JsonObject ServiceTokenBody(string name, string duration, bool allowNoExpiry)
    {
        P1.Required(name, nameof(name), 256);
        var d = P1.Required(duration, nameof(duration)).Trim();
        if (d == "forever") P2.Allow(allowNoExpiry, "a service token that never expires", nameof(allowNoExpiry));
        else if (!System.Text.RegularExpressions.Regex.IsMatch(d, @"^\d+h$", System.Text.RegularExpressions.RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)))
            throw new ArgumentException("Duration in hours, for example \"8760h\", or \"forever\".", nameof(duration));
        return new JsonObject { ["name"] = name, ["duration"] = d };
    }

    private static JsonObject RotateBody(TimeSpan? grace) =>
        grace is { } g
            ? new JsonObject { ["previous_client_secret_expires_at"] = DateTimeOffset.UtcNow.Add(g).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture) }
            : new JsonObject();

    private static IssuedServiceToken Issued(JsonElement result, string method, string path)
    {
        if (result.ValueKind != JsonValueKind.Object || !result.TryGetProperty("client_secret", out var s) || s.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(s.GetString()))
            throw new CloudflareApiException(HttpStatusCode.OK, method, CloudflarePath.Normalize(path),
                [new CloudflareError { Message = "The answer carries no client secret; the token may exist without a known secret. Rotate or delete it." }]);
        var secret = new CloudflareOneTimeSecret(s.GetString()!, "access-service-token-secret");
        return new IssuedServiceToken(P1.As<AccessServiceToken>(ZT.Strip(result)), secret);
    }

    // ------------------------------------------------------------------ identity providers

    public CloudflareChangePreview PreviewEnsureIdentityProvider(string name, string type, object? config = null, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "identity_providers"), ZT.Redact(IdpBody(name, type, config)),
            $"Create identity provider \"{name}\" ({type}); secrets in the configuration are shown as {P1.Redacted}.");

    /// <summary>
    /// Returns the identity provider with this name and type or creates it. The configuration (for example <c>client_secret</c>) goes into the request body
    /// only; previews redact it and the model never contains it. An existing provider is not changed.
    /// </summary>
    public async Task<(AccessIdentityProvider Provider, bool Created)> EnsureIdentityProviderAsync(string name, string type, object? config = null, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "identity_providers");
        EnsureWritable(HttpMethod.Post, path);
        var body = IdpBody(name, type, config);
        var existing = (await ListIdentityProvidersAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(p => p.Name == name && p.Type == type);
        if (existing is not null) return (existing, false);
        try { return (await ZT.SendAsync<AccessIdentityProvider>(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false), true); }
        catch (CloudflareConflictException)
        {
            var again = (await ListIdentityProvidersAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(p => p.Name == name && p.Type == type);
            return again is null ? throw ZT.Conflict("POST", path, $"Identity provider \"{name}\" is reported as existing but was not found.") : (again, false);
        }
    }

    /// <summary>Deletes an identity provider after a fresh read of all providers: the last one is the last login method and needs <paramref name="allowRemoveLast"/>. False when it did not exist.</summary>
    public async Task<bool> RemoveIdentityProviderAsync(string providerId, bool allowRemoveLast = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "identity_providers", P1.Required(providerId, nameof(providerId)));
        EnsureWritable(HttpMethod.Delete, path);
        var all = await ListIdentityProvidersAsync(accountId, ct).ConfigureAwait(false);
        var target = all.FirstOrDefault(p => p.Id == providerId);
        if (target is null) return false;
        if (all.Count == 1) P2.Allow(allowRemoveLast, $"\"{target.Name}\" is the last identity provider; without it nobody can log in", nameof(allowRemoveLast));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    private static JsonObject IdpBody(string name, string type, object? config)
    {
        P1.Required(name, nameof(name), 256);
        if (!IdpTypes.Contains(type)) throw new ArgumentException($"Unknown identity provider type \"{type}\".", nameof(type));
        return new JsonObject { ["name"] = name, ["type"] = type, ["config"] = ZT.ToNode(config) ?? new JsonObject() };
    }

    // ------------------------------------------------------------------ mTLS certificates

    public Task<IReadOnlyList<AccessCertificate>> ListCertificatesAsync(string? accountId = null, CancellationToken ct = default) =>
        ZT.ListAllAsync<AccessCertificate>(Api, AccountPath(accountId, "access", "certificates"), 50, ct);

    public Task<AccessCertificate> GetCertificateAsync(string certificateId, string? accountId = null, CancellationToken ct = default) =>
        ZT.SendAsync<AccessCertificate>(Api, HttpMethod.Get, AccountPath(accountId, "access", "certificates", certificateId), null, ct);

    /// <summary>Plan of a new mTLS root certificate: shows size and SHA-256 of the PEM, not the PEM itself.</summary>
    public CloudflareChangePreview PreviewEnsureCertificate(string name, string certificatePem, IEnumerable<string>? hostnames = null, string? accountId = null)
    {
        var (_, hosts, sha) = CertificateBody(name, certificatePem, hostnames);
        return new("POST", AccountPath(accountId, "access", "certificates"),
            new JsonObject { ["name"] = name, ["certificate"] = $"[PEM, {Encoding.UTF8.GetByteCount(certificatePem)} bytes, sha256 {sha}]", ["associated_hostnames"] = P1.Arr(hosts) },
            $"Add mTLS root certificate \"{name}\" for {P1.Join(hosts)}.");
    }

    /// <summary>
    /// Returns the root certificate with this name or adds it. Only a public CA certificate is accepted (PEM <c>CERTIFICATE</c>); input with a private key is
    /// refused locally. Associating hostnames lets Access ask for client certificates there; enforce it with a policy rule <see cref="AccessRules.ValidCertificate"/>.
    /// </summary>
    public async Task<(AccessCertificate Certificate, bool Created)> EnsureCertificateAsync(string name, string certificatePem, IEnumerable<string>? hostnames = null,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "certificates");
        EnsureWritable(HttpMethod.Post, path);
        var (body, _, _) = CertificateBody(name, certificatePem, hostnames);
        var existing = (await ListCertificatesAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(c => c.Name == name);
        if (existing is not null) return (existing, false);
        return (await ZT.SendAsync<AccessCertificate>(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>
    /// Sets the hostnames of a root certificate after a fresh read (written only on change). Removing a hostname ends mTLS there and needs
    /// <paramref name="allowRemovals"/>.
    /// </summary>
    public async Task<(AccessCertificate Certificate, bool Changed)> SetCertificateHostnamesAsync(string certificateId, IEnumerable<string> hostnames, bool allowRemovals = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "certificates", P1.Required(certificateId, nameof(certificateId)));
        EnsureWritable(HttpMethod.Put, path);
        var next = hostnames.Select(h => P1.Hostname(h, nameof(hostnames))).Distinct().OrderBy(h => h, StringComparer.Ordinal).ToList();
        var current = await GetCertificateAsync(certificateId, accountId, ct).ConfigureAwait(false);
        var removed = current.AssociatedHostnames.Where(h => !next.Contains(h, StringComparer.OrdinalIgnoreCase)).ToList();
        if (removed.Count > 0) P2.Allow(allowRemovals, $"removing {P1.Join(removed)} from certificate \"{current.Name}\" ends mTLS there", nameof(allowRemovals));
        if (removed.Count == 0 && next.All(h => current.AssociatedHostnames.Contains(h, StringComparer.OrdinalIgnoreCase))) return (current, false);
        var body = new JsonObject { ["name"] = current.Name, ["associated_hostnames"] = P1.Arr(next) };
        return (await ZT.SendAsync<AccessCertificate>(Api, HttpMethod.Put, path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>Deletes a root certificate after a fresh read; one that still has hostnames needs <paramref name="allowRemovals"/>. False when it did not exist.</summary>
    public async Task<bool> RemoveCertificateAsync(string certificateId, bool allowRemovals = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "certificates", P1.Required(certificateId, nameof(certificateId)));
        EnsureWritable(HttpMethod.Delete, path);
        var current = await ZT.GetOrNullAsync<AccessCertificate>(Api, path, ct).ConfigureAwait(false);
        if (current is null) return false;
        if (current.AssociatedHostnames.Count > 0)
            P2.Allow(allowRemovals, $"certificate \"{current.Name}\" still protects {P1.Join(current.AssociatedHostnames)}", nameof(allowRemovals));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    public async Task<List<AccessCertificateHostnameSetting>> GetCertificateSettingsAsync(string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<AccessCertificateHostnameSetting>>(AccountPath(accountId, "access", "certificates", "settings"), ct).ConfigureAwait(false) ?? [];

    private static (JsonObject Body, List<string> Hosts, string Sha) CertificateBody(string name, string pem, IEnumerable<string>? hostnames)
    {
        P1.Required(name, nameof(name), 256);
        var text = P1.Required(pem, nameof(pem)).Trim();
        if (text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Only the public CA certificate is uploaded; the input contains a private key.", nameof(pem));
        if (!text.StartsWith("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal)) throw new ArgumentException("A PEM certificate (-----BEGIN CERTIFICATE-----).", nameof(pem));
        var hosts = (hostnames ?? []).Select(h => P1.Hostname(h, nameof(hostnames))).Distinct().ToList();
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
        return (new JsonObject { ["name"] = name, ["certificate"] = text, ["associated_hostnames"] = P1.Arr(hosts) }, hosts, sha);
    }

    // ------------------------------------------------------------------ organization, users, sessions

    public Task<AccessOrganization> GetOrganizationAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<AccessOrganization>(AccountPath(accountId, "access", "organizations"), ct);

    /// <summary>Plan of an organization change (reads the organization to name tightening/loosening; sends no write).</summary>
    public async Task<CloudflareChangePreview> PreviewUpdateOrganizationAsync(AccessOrganizationChange change, string? accountId = null, CancellationToken ct = default)
    {
        var current = await GetOrganizationAsync(accountId, ct).ConfigureAwait(false);
        var (body, notes) = OrganizationBody(current, change);
        return new("PATCH", AccountPath(accountId, "access", "organizations"), body,
            body.Count == 0 ? "No change." : $"Change {string.Join(", ", body.Select(p => p.Key))} of the Zero Trust organization." + (notes.Count > 0 ? " WARNING: " + string.Join("; ", notes.Select(n => n.Text)) + "." : ""));
    }

    /// <summary>
    /// Changes the organization (PATCH, only fields that differ from a fresh read are sent). Changing the team domain needs <paramref name="allowDisconnect"/>;
    /// turning on "deny unmatched requests" or "MFA for all apps" tightens the default and needs <paramref name="allowBlock"/>; turning them off needs
    /// <paramref name="allowLoosen"/>.
    /// </summary>
    public async Task<(AccessOrganization Organization, bool Changed)> UpdateOrganizationAsync(AccessOrganizationChange change, bool allowDisconnect = false, bool allowBlock = false,
        bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "organizations");
        EnsureWritable(HttpMethod.Patch, path);
        var current = await GetOrganizationAsync(accountId, ct).ConfigureAwait(false);
        var (body, notes) = OrganizationBody(current, change);
        foreach (var (flag, text) in notes)
            P2.Allow(flag switch { "allowDisconnect" => allowDisconnect, "allowBlock" => allowBlock, _ => allowLoosen }, text, flag);
        if (body.Count == 0) return (current, false);
        return (await Api.PatchAsync<AccessOrganization>(path, body, ct).ConfigureAwait(false), true);
    }

    private static (JsonObject Body, List<(string Flag, string Text)> Notes) OrganizationBody(AccessOrganization current, AccessOrganizationChange c)
    {
        var body = new JsonObject();
        var notes = new List<(string, string)>();
        void Str(string name, string? next, string? now) { if (next is not null && next != now) body[name] = next; }
        void Bool(string name, bool? next, bool? now) { if (next is { } n && n != (now ?? false)) body[name] = n; }

        Str("name", c.Name, current.Name);
        if (c.AuthDomain is { } domain)
        {
            var host = P1.Hostname(domain, nameof(c));
            if (!string.Equals(host, current.AuthDomain, StringComparison.OrdinalIgnoreCase))
            {
                body["auth_domain"] = host;
                notes.Add(("allowDisconnect", "changing the team domain changes the login address and the issuer of every Access JWT"));
            }
        }
        Str("session_duration", c.SessionDuration, current.SessionDuration);
        Str("warp_auth_session_duration", c.WarpAuthSessionDuration, current.WarpAuthSessionDuration);
        Bool("auto_redirect_to_identity", c.AutoRedirectToIdentity, current.AutoRedirectToIdentity);
        Bool("is_ui_read_only", c.IsUiReadOnly, current.IsUiReadOnly);
        if (body.ContainsKey("is_ui_read_only") && c.UiReadOnlyToggleReason is { } reason) body["ui_read_only_toggle_reason"] = reason;
        Bool("allow_authenticate_via_warp", c.AllowAuthenticateViaWarp, current.AllowAuthenticateViaWarp);
        Bool("deny_unmatched_requests", c.DenyUnmatchedRequests, current.DenyUnmatchedRequests);
        if (body["deny_unmatched_requests"] is { } deny)
            notes.Add(deny.GetValue<bool>()
                ? ("allowBlock", "denying unmatched requests blocks every hostname of the account without an Access application")
                : ("allowLoosen", "turning off \"deny unmatched requests\" opens hostnames without an Access application"));
        Bool("mfa_required_for_all_apps", c.MfaRequiredForAllApps, current.MfaRequiredForAllApps);
        if (body["mfa_required_for_all_apps"] is { } mfa)
            notes.Add(mfa.GetValue<bool>()
                ? ("allowBlock", "requiring MFA for all applications locks out users without a second factor")
                : ("allowLoosen", "turning off MFA for all applications loosens every application"));
        if (c.LoginDesign is { } design && !P1.Covers(P1.Node(current.LoginDesign), design)) body["login_design"] = design.DeepClone();
        return (body, notes);
    }

    /// <summary>Users (seats) of the organization, optionally filtered (personal data: do not log).</summary>
    public Task<IReadOnlyList<AccessUser>> ListUsersAsync(string? search = null, string? email = null, string? accountId = null, CancellationToken ct = default) =>
        Api.ListAllToListAsync<AccessUser>(CloudflarePath.WithQuery(AccountPath(accountId, "access", "users"), ("search", search), ("email", email)), 50, ct);

    /// <summary>Active Access sessions of a user (applications and expiry; Cloudflare returns no session token).</summary>
    public async Task<List<AccessActiveSession>> ListActiveSessionsAsync(string userId, string? accountId = null, CancellationToken ct = default) =>
        await ZT.GetListAsync<AccessActiveSession>(Api, AccountPath(accountId, "access", "users", P1.Required(userId, nameof(userId)), "active_sessions"), ct).ConfigureAwait(false);

    /// <summary>Plan of a session revocation; the e-mail address is not part of the preview.</summary>
    public CloudflareChangePreview PreviewRevokeUserSessions(string email, bool includeDevices = false, string? accountId = null) =>
        new("POST", AccountPath(accountId, "access", "organizations", "revoke_user"), new JsonObject { ["email"] = P2.Mask(P1.Required(email, nameof(email))), ["devices"] = includeDevices },
            $"Revoke all Access sessions of one user{(includeDevices ? " and their device sessions" : "")}.");

    /// <summary>Logs one user out of every application (POST, not retried). Needs <paramref name="allowDisconnect"/>.</summary>
    public async Task RevokeUserSessionsAsync(string email, bool includeDevices = false, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "organizations", "revoke_user");
        EnsureWritable(HttpMethod.Post, path);
        var address = P1.Required(email, nameof(email)).Trim();
        if (!address.Contains('@')) throw new ArgumentException("An e-mail address.", nameof(email));
        P2.Allow(allowDisconnect, "revoking the sessions of a user logs them out of every application", nameof(allowDisconnect));
        await Api.SendAsync<JsonElement>(HttpMethod.Post, path, new JsonObject { ["email"] = address, ["devices"] = includeDevices }, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ shared

    private static string Describe(string what, AccessPolicyInput p)
    {
        var everyone = AccessPolicyRisk.AdmitsEveryone(p.Decision, p.Include, p.Require ?? []);
        return $"{what} \"{p.Name}\": {p.Decision}, {p.Include.Count} include, {p.Exclude?.Count ?? 0} exclude, {p.Require?.Count ?? 0} require rule(s)."
               + (everyone ? " WARNING: admits everyone." : "")
               + (AccessPolicyRisk.DeniesEveryone(p.Decision, p.Include) ? " WARNING: denies everyone." : "");
    }

    private static JsonObject PolicyBody(AccessPolicyInput p, bool allowLoosen, bool allowBlock, AccessPolicy? current)
    {
        P1.Required(p.Name, nameof(p), 350);
        if (AccessPolicyRisk.Rank(p.Decision) < 0) throw new ArgumentException("Decision must be allow, deny, non_identity or bypass.", nameof(p));
        if (p.Include is not { Count: > 0 }) throw new ArgumentException("At least one include rule (see AccessRules).", nameof(p));
        if (current is null)
        {
            if (AccessPolicyRisk.AdmitsEveryone(p.Decision, p.Include, p.Require ?? []))
                P2.Allow(allowLoosen, $"policy \"{p.Name}\" admits everyone ({p.Decision})", nameof(allowLoosen));
        }
        else if (AccessPolicyRisk.Loosening(AccessPolicyRisk.Of(current), AccessPolicyRisk.Of(p)) is { } why)
            P2.Allow(allowLoosen, $"the change loosens policy \"{current.Name}\": {why}", nameof(allowLoosen));
        if (AccessPolicyRisk.DeniesEveryone(p.Decision, p.Include) && (current is null || !AccessPolicyRisk.DeniesEveryone(current.Decision, current.Include)))
            P2.Allow(allowBlock, $"policy \"{p.Name}\" denies everyone", nameof(allowBlock));

        // exclude/require are always sent (also empty), so that a change that removes them is detected and written.
        var body = new JsonObject { ["name"] = p.Name, ["decision"] = p.Decision, ["include"] = Rules(p.Include), ["exclude"] = Rules(p.Exclude ?? []), ["require"] = Rules(p.Require ?? []) };
        if (p.Precedence is { } prec) body["precedence"] = prec;
        if (p.SessionDuration is { } sd) body["session_duration"] = sd;
        return body;
    }

    private static JsonObject GroupBody(AccessGroupInput g, bool allowLoosen, AccessGroup? current)
    {
        P1.Required(g.Name, nameof(g), 350);
        if (g.Include is not { Count: > 0 }) throw new ArgumentException("At least one include rule (see AccessRules).", nameof(g));
        var everyone = AccessPolicyRisk.Has(g.Include, "everyone") && g.Require is not { Count: > 0 };
        if (everyone && (current is null || !AccessPolicyRisk.Has(current.Include, "everyone")))
            P2.Allow(allowLoosen, $"group \"{g.Name}\" includes everyone", nameof(allowLoosen));
        if (current is not null && AccessPolicyRisk.Loosening(("allow", current.Include, current.Exclude, current.Require), ("allow", g.Include, g.Exclude ?? [], g.Require ?? [])) is { } why)
            P2.Allow(allowLoosen, $"the change loosens group \"{current.Name}\": {why}", nameof(allowLoosen));
        return new JsonObject { ["name"] = g.Name, ["include"] = Rules(g.Include), ["exclude"] = Rules(g.Exclude ?? []), ["require"] = Rules(g.Require ?? []) };
    }

    private static JsonArray Rules(IEnumerable<JsonElement> rules) => new(rules.Select(r => P1.Node(r)).ToArray());
}

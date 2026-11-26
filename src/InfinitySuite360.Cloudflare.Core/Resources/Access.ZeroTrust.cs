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

/// <summary>The parts of an Access policy (or group) that decide who gets in; compared by the loosening and lock-out checks.</summary>
internal readonly record struct AccessPolicyShape(string Decision, IReadOnlyList<JsonElement> Include, IReadOnlyList<JsonElement> Exclude, IReadOnlyList<JsonElement> Require,
    int? Precedence = null, string? SessionDuration = null);

/// <summary>How permissive an Access policy is; used by the loosening and lock-out checks.</summary>
internal static class AccessPolicyRisk
{
    private static readonly string[] Decisions = ["deny", "allow", "non_identity", "bypass"];

    /// <summary>Mail providers where anybody can open an address: an <c>email_domain</c> rule for them admits the public (H2c, 0.8.1).</summary>
    private static readonly HashSet<string> PublicMailDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "ymail.com", "icloud.com", "me.com", "aol.com",
        "gmx.de", "gmx.net", "gmx.com", "gmx.at", "gmx.ch", "web.de", "t-online.de", "proton.me", "protonmail.com", "pm.me", "yandex.com", "yandex.ru",
        "mail.com", "mail.ru", "zoho.com", "fastmail.com", "tutanota.com", "tuta.io", "posteo.de", "qq.com", "163.com",
    };

    public static int Rank(string decision) => Array.IndexOf(Decisions, decision);

    public static bool Has(IEnumerable<JsonElement> rules, string name) =>
        rules.Any(r => r.ValueKind == JsonValueKind.Object && r.TryGetProperty(name, out _));

    public static bool Admits(string decision) => decision is "allow" or "non_identity" or "bypass";

    /// <summary>
    /// A rule that matches (nearly) anybody: <c>everyone</c>, an <c>ip</c> range shorter than /8 (IPv6 /16, including 0.0.0.0/0 and ::/0), an
    /// <c>email_domain</c> of a public mail provider (or empty/wildcard) and, as an include rule, <c>any_valid_service_token</c>.
    /// </summary>
    public static bool IsBroad(JsonElement rule, bool asRequire = false)
    {
        if (rule.ValueKind != JsonValueKind.Object) return false;
        foreach (var p in rule.EnumerateObject())
        {
            switch (p.Name)
            {
                case "everyone": return true;
                case "any_valid_service_token" when !asRequire: return true;
                case "ip" when P2.Str(p.Value, "ip") is { } ip && ZT.IsBroadCidr(ip): return true;
                case "email_domain":
                    var domain = (P2.Str(p.Value, "domain") ?? "").Trim().TrimStart('@');
                    if (domain.Length == 0 || domain.Contains('*') || PublicMailDomains.Contains(domain)) return true;
                    break;
            }
        }
        return false;
    }

    /// <summary>
    /// The policy lets (nearly) everybody in: bypass, or allow/non_identity with a broad include rule (<see cref="IsBroad"/>) and no require rule that
    /// narrows it (a require of <c>everyone</c> or 0.0.0.0/0 does not count).
    /// </summary>
    public static bool AdmitsEveryone(string decision, IReadOnlyList<JsonElement> include, IReadOnlyList<JsonElement> require) =>
        decision == "bypass" || (Admits(decision) && include.Any(r => IsBroad(r)) && require.All(r => IsBroad(r, asRequire: true)));

    public static bool AdmitsEveryone(AccessPolicyShape s) => AdmitsEveryone(s.Decision, s.Include, s.Require);

    public static bool DeniesEveryone(string decision, IReadOnlyList<JsonElement> include) =>
        decision == "deny" && include.Any(r => Has([r], "everyone") || (r.ValueKind == JsonValueKind.Object && r.TryGetProperty("ip", out var ip) && ZT.IsBroadCidr(P2.Str(ip, "ip"))));

    private static bool Same(JsonElement a, JsonElement b) => JsonNode.DeepEquals(JsonNode.Parse(a.GetRawText()), JsonNode.Parse(b.GetRawText()));

    private static bool Removed(IReadOnlyList<JsonElement> before, IReadOnlyList<JsonElement> after) => before.Any(b => !after.Any(a => Same(a, b)));

    private static bool Added(IReadOnlyList<JsonElement> before, IReadOnlyList<JsonElement> after) => Removed(after, before);

    /// <summary>
    /// Why <paramref name="next"/> is looser than <paramref name="current"/>, or null (H2, 0.8.1): a more permissive decision; admitting everyone; for an
    /// admitting policy added include rules, removed require/exclude rules, an earlier precedence; for a deny policy removed include rules, added
    /// exclude/require rules, a later precedence; a longer session.
    /// </summary>
    public static string? Loosening(AccessPolicyShape current, AccessPolicyShape next)
    {
        if (Rank(next.Decision) > Rank(current.Decision)) return $"decision {current.Decision} → {next.Decision}";
        if (AdmitsEveryone(next) && !AdmitsEveryone(current)) return "it would admit everyone";
        if (current.Decision == "deny" && next.Decision == "deny")
        {
            if (Removed(current.Include, next.Include)) return "a deny policy would match fewer requests (include rules removed)";
            if (Added(current.Exclude, next.Exclude)) return "a deny policy would match fewer requests (exclude rules added)";
            if (Added(current.Require, next.Require)) return "a deny policy would match fewer requests (require rules added)";
            if (next.Precedence is { } p && current.Precedence is { } c && p > c) return $"a deny policy would be evaluated later (precedence {c} → {p})";
            return null;
        }
        if (!Admits(next.Decision)) return null;
        if (Added(current.Include, next.Include)) return "include rules would be added (admits more)";
        if (Removed(current.Require, next.Require)) return "require rules would be removed";
        if (Removed(current.Exclude, next.Exclude)) return "exclude rules would be removed";
        if (next.Precedence is { } np && current.Precedence is { } cp && np < cp) return $"an admitting policy would be evaluated earlier (precedence {cp} → {np})";
        if (ZT.Longer(current.SessionDuration, next.SessionDuration)) return $"longer sessions ({current.SessionDuration ?? "default"} → {next.SessionDuration})";
        return null;
    }

    public static AccessPolicyShape Of(AccessPolicy p) => new(p.Decision, p.Include, p.Exclude, p.Require, p.Precedence, p.SessionDuration);

    public static AccessPolicyShape Of(AccessPolicyInput p) => new(p.Decision, p.Include, p.Exclude ?? [], p.Require ?? [], p.Precedence, p.SessionDuration);

    /// <summary>Members of a policy that Cloudflare sets itself; they are not sent back with a PUT.</summary>
    public static readonly string[] ReadOnlyMembers = ["id", "uid", "created_at", "updated_at", "app_count", "reusable"];
}

public sealed partial class AccessClient
{
    private static readonly HashSet<string> AppTypes = ["self_hosted", "saas", "ssh", "vnc", "app_launcher", "warp", "biso", "bookmark", "dash_sso", "infrastructure", "rdp", "mcp", "mcp_portal", "proxy_endpoint"];
    private static readonly HashSet<string> IdpTypes = ["onetimepin", "azureAD", "saml", "centrify", "facebook", "github", "google-apps", "google", "linkedin", "oidc", "duo", "okta", "onelogin", "pingone", "yandex", "cloudflare", "passkeys"];

    // ------------------------------------------------------------------ applications

    /// <summary>Plan of a new application (sends nothing).</summary>
    public CloudflareChangePreview PreviewEnsureApplication(AccessApplicationInput app, bool allowNoPolicy = false, string? accountId = null)
    {
        var (body, inline) = AppBody(app, allowNoPolicy, allowLoosen: true, allowBlock: true);
        return new("POST", AccountPath(accountId, "access", "apps"), ZT.Redact(body),
            $"Create Access application \"{app.Name}\" for {app.Domain} ({app.Type}) with {ZT.Plural(app.Policies?.Count ?? 0, "policy", "policies")}. "
            + "WARNING: from then on the hostname needs an Access login."
            + (inline.Any(p => AccessPolicyRisk.AdmitsEveryone(p)) ? " WARNING: an inline policy admits everyone (needs allowLoosen)." : "")
            + (inline.Any(p => AccessPolicyRisk.DeniesEveryone(p.Decision, p.Include)) ? " WARNING: an inline policy denies everyone (needs allowBlock)." : ""));
    }

    /// <summary>
    /// Returns the application for this domain and type or creates it; an existing application is not changed. An application without policies denies
    /// everyone (Cloudflare's default), so that needs <paramref name="allowNoPolicy"/>. Creating protects a hostname that may be public today: check the
    /// preview first. M4 (0.8.1): inline policy objects get the checks of <see cref="AddApplicationPolicyAsync"/> (admitting everyone needs
    /// <paramref name="allowLoosen"/>, denying everyone <paramref name="allowBlock"/>); policies referenced by id are read before the POST and one that admits
    /// everyone needs <paramref name="allowLoosen"/> as well (fail-closed when it cannot be read).
    /// </summary>
    public async Task<(AccessApplication Application, bool Created)> EnsureApplicationAsync(AccessApplicationInput app, bool allowNoPolicy = false,
        string? accountId = null, bool allowLoosen = false, bool allowBlock = false, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps");
        EnsureWritable(HttpMethod.Post, path);
        var (body, _) = AppBody(app, allowNoPolicy, allowLoosen, allowBlock);
        var existing = await FindApplicationAsync(app, accountId, ct).ConfigureAwait(false);
        if (existing is not null) return (existing, false);
        await CheckReferencedPoliciesAsync(app, allowLoosen, accountId, ct).ConfigureAwait(false);
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

    /// <summary>
    /// The application body. Policy entries are an id (string), a reference object (<c>{"id": …, "precedence": …}</c>) or an inline policy object with
    /// <c>decision</c>/<c>include</c>; inline policies are validated like <see cref="AddApplicationPolicyAsync"/> (M4, 0.8.1). Returns the inline shapes for the preview.
    /// </summary>
    private static (JsonObject Body, List<AccessPolicyShape> Inline) AppBody(AccessApplicationInput app, bool allowNoPolicy, bool allowLoosen, bool allowBlock)
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
        var inline = new List<AccessPolicyShape>();
        if (app.Policies is { Count: > 0 } policies)
        {
            var nodes = new JsonArray();
            foreach (var entry in policies)
            {
                var node = ZT.ToNode(entry);
                switch (node)
                {
                    case JsonValue s when s.TryGetValue<string>(out var id):
                        P1.Required(id, nameof(app));
                        nodes.Add(JsonValue.Create(id));
                        break;
                    case JsonObject o when o.ContainsKey("decision") || o.ContainsKey("include"):
                        var input = InlinePolicy(o);
                        var checkedBody = PolicyBody(input, allowLoosen, allowBlock, null);
                        if (o["precedence"] is { } prec) checkedBody["precedence"] = prec.DeepClone();
                        inline.Add(AccessPolicyRisk.Of(input));
                        nodes.Add(checkedBody);
                        break;
                    case JsonObject o when o["id"] is JsonValue idValue && idValue.TryGetValue<string>(out var refId) && !string.IsNullOrWhiteSpace(refId):
                        nodes.Add(o.DeepClone());
                        break;
                    default:
                        throw new ArgumentException("A policy entry is the id of a reusable policy, {\"id\": …, \"precedence\": …} or a policy object with decision and include.", nameof(app));
                }
            }
            body["policies"] = nodes;
        }
        return (body, inline);
    }

    private static AccessPolicyInput InlinePolicy(JsonObject o)
    {
        static List<JsonElement> List(JsonNode? n) => n is JsonArray a ? a.Select(x => JsonSerializer.SerializeToElement(x, CloudflareJson.Options)).ToList() : [];
        return new AccessPolicyInput
        {
            Name = o["name"] is JsonValue n && n.TryGetValue<string>(out var name) && !string.IsNullOrWhiteSpace(name) ? name : "(inline policy)",
            Decision = o["decision"] is JsonValue d && d.TryGetValue<string>(out var decision) ? decision : "",
            Include = List(o["include"]),
            Exclude = List(o["exclude"]),
            Require = List(o["require"]),
            SessionDuration = o["session_duration"] is JsonValue sd && sd.TryGetValue<string>(out var s) ? s : null,
        };
    }

    /// <summary>Reads every reusable policy the new application refers to by id; one that admits everyone needs <paramref name="allowLoosen"/> (fail-closed).</summary>
    private async Task CheckReferencedPoliciesAsync(AccessApplicationInput app, bool allowLoosen, string? accountId, CancellationToken ct)
    {
        foreach (var entry in app.Policies ?? [])
        {
            var id = ZT.ToNode(entry) switch
            {
                JsonValue s when s.TryGetValue<string>(out var v) => v,
                JsonObject o when !(o.ContainsKey("decision") || o.ContainsKey("include")) && o["id"] is JsonValue idValue && idValue.TryGetValue<string>(out var v) => v,
                _ => null,
            };
            if (id is null) continue;
            var policy = await GetPolicyAsync(id, accountId, ct).ConfigureAwait(false);
            if (AccessPolicyRisk.AdmitsEveryone(AccessPolicyRisk.Of(policy)))
                P2.Allow(allowLoosen, $"reusable policy \"{policy.Name}\" ({policy.Decision}) admits everyone to application \"{app.Name}\"", nameof(allowLoosen));
        }
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
    /// Replaces an application policy after a fresh read. Loosening (more permissive decision, admitting everyone, added include rules, removed
    /// require/exclude rules, an earlier precedence, longer sessions; for a deny: fewer include rules, added exclude/require rules, a later precedence)
    /// needs <paramref name="allowLoosen"/>; a deny for everyone needs <paramref name="allowBlock"/>. Written only on change. The PUT keeps every member of
    /// the current policy the input does not set (for example <c>approval_required</c>, <c>isolation_required</c>, <c>purpose_justification_required</c>,
    /// <c>mfa_config</c>, <c>connection_rules</c>) instead of resetting it.
    /// </summary>
    public async Task<(AccessPolicy Policy, bool Changed)> ChangeApplicationPolicyAsync(string appId, string policyId, AccessPolicyInput policy, bool allowLoosen = false, bool allowBlock = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "apps", P1.Required(appId, nameof(appId)), "policies", P1.Required(policyId, nameof(policyId)));
        EnsureWritable(HttpMethod.Put, path);
        return await ReplacePolicyAsync(path, policy, allowLoosen, allowBlock, ct).ConfigureAwait(false);
    }

    private async Task<(AccessPolicy Policy, bool Changed)> ReplacePolicyAsync(string path, AccessPolicyInput policy, bool allowLoosen, bool allowBlock, CancellationToken ct)
    {
        var currentRaw = await ZT.ResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        var current = P1.As<AccessPolicy>(currentRaw);
        var body = PolicyBody(policy, allowLoosen, allowBlock, current);
        if (P1.Covers(P1.Node(currentRaw), body)) return (current, false);
        var merged = ZT.Merge(currentRaw, body, AccessPolicyRisk.ReadOnlyMembers);
        return (await ZT.SendAsync<AccessPolicy>(Api, HttpMethod.Put, path, merged, ct).ConfigureAwait(false), true);
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
        return await ReplacePolicyAsync(path, policy, allowLoosen, allowBlock, ct).ConfigureAwait(false);
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

    /// <summary>
    /// Replaces a group after a fresh read. Including everyone, adding include rules or removing exclude/require rules loosens every policy that uses it
    /// and needs <paramref name="allowLoosen"/>. M5 (0.8.1): any change of the rules of a group that policies, applications or other groups use changes who
    /// passes them and needs <paramref name="allowInUse"/> (the users are read, fail-closed). The PUT keeps members the input does not set. Written only on change.
    /// </summary>
    public async Task<(AccessGroup Group, bool Changed)> ChangeGroupAsync(string groupId, AccessGroupInput group, bool allowLoosen = false, string? accountId = null,
        bool allowInUse = false, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "groups", P1.Required(groupId, nameof(groupId)));
        EnsureWritable(HttpMethod.Put, path);
        var currentRaw = await ZT.ResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        var current = P1.As<AccessGroup>(currentRaw);
        var body = GroupBody(group, allowLoosen, current);
        if (P1.Covers(P1.Node(currentRaw), body)) return (current, false);
        var now = P1.Node(currentRaw);
        var rulesChange = new[] { "include", "exclude", "require" }.Any(k => !JsonNode.DeepEquals(now?[k] ?? new JsonArray(), body[k] ?? new JsonArray()));
        if (rulesChange && !allowInUse && await GroupUsersAsync(groupId, accountId, ct).ConfigureAwait(false) is { Count: > 0 } users)
            throw new InvalidOperationException($"Refused: group \"{current.Name}\" is used by {string.Join(", ", users)}; changing its rules changes who passes them. Pass allowInUse: true deliberately.");
        var merged = ZT.Merge(currentRaw, body, AccessPolicyRisk.ReadOnlyMembers);
        return (await ZT.SendAsync<AccessGroup>(Api, HttpMethod.Put, path, merged, ct).ConfigureAwait(false), true);
    }

    /// <summary>
    /// Deletes a group. When reusable policies, application policies or other groups refer to it, this needs <paramref name="allowInUse"/> (the check reads
    /// policies, applications and groups; if they cannot be read the call fails). False when it did not exist.
    /// </summary>
    public async Task<bool> RemoveGroupAsync(string groupId, bool allowInUse = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "groups", P1.Required(groupId, nameof(groupId)));
        EnsureWritable(HttpMethod.Delete, path);
        if (!allowInUse && await GroupUsersAsync(groupId, accountId, ct).ConfigureAwait(false) is { Count: > 0 } users)
            throw new InvalidOperationException($"Refused: group {groupId} is used by {string.Join(", ", users)}. Remove the references first or pass allowInUse: true deliberately.");
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    /// <summary>Reusable policies, applications (with their policies) and other groups that refer to <paramref name="groupId"/> (fresh reads, fail-closed).</summary>
    private async Task<List<string>> GroupUsersAsync(string groupId, string? accountId, CancellationToken ct)
    {
        var users = new List<string>();
        foreach (var p in await ListPoliciesAsync(accountId, ct).ConfigureAwait(false))
            if (ZT.References(ToElement(new { p.Include, p.Exclude, p.Require }), "group", "id", groupId)) users.Add($"policy \"{p.Name}\"");
        foreach (var a in await ListApplicationsAsync(accountId, ct).ConfigureAwait(false))
            if (a.Policies.Any(x => ZT.References(x, "group", "id", groupId))) users.Add($"application \"{a.Name}\"");
        foreach (var g in await ListGroupsAsync(accountId, ct).ConfigureAwait(false))
            if (g.Id != groupId && ZT.References(ToElement(new { g.Include, g.Exclude, g.Require }), "group", "id", groupId)) users.Add($"group \"{g.Name}\"");
        return users;
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
    /// Deletes a service token after a fresh read: a token that was ever used (<c>last_seen_at</c> set) or is referenced by a reusable policy, a group or a
    /// policy bound to an application (L1, 0.8.1) cuts machines off and needs <paramref name="allowDisconnect"/> (fail-closed). False when it did not exist.
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
            var used = new List<string>();
            foreach (var p in await ListPoliciesAsync(accountId, ct).ConfigureAwait(false))
                if (ZT.References(ToElement(new { p.Include, p.Exclude, p.Require }), "service_token", "token_id", tokenId)) used.Add($"policy \"{p.Name}\"");
            foreach (var g in await ListGroupsAsync(accountId, ct).ConfigureAwait(false))
                if (ZT.References(ToElement(new { g.Include, g.Exclude, g.Require }), "service_token", "token_id", tokenId)) used.Add($"group \"{g.Name}\"");
            foreach (var a in await ListApplicationsAsync(accountId, ct).ConfigureAwait(false))
                if (a.Policies.Any(x => ZT.References(x, "service_token", "token_id", tokenId))) used.Add($"application \"{a.Name}\"");
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

    /// <summary>
    /// Deletes an identity provider after a fresh read of all providers and applications: the last one is the last login method, and M8 (0.8.1) an
    /// application whose <c>allowed_idps</c> list only this provider (or only providers that no longer exist) can no longer be logged into; both need
    /// <paramref name="allowRemoveLast"/> (fail-closed). False when it did not exist.
    /// </summary>
    public async Task<bool> RemoveIdentityProviderAsync(string providerId, bool allowRemoveLast = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "access", "identity_providers", P1.Required(providerId, nameof(providerId)));
        EnsureWritable(HttpMethod.Delete, path);
        var all = await ListIdentityProvidersAsync(accountId, ct).ConfigureAwait(false);
        var target = all.FirstOrDefault(p => p.Id == providerId);
        if (target is null) return false;
        if (all.Count == 1) P2.Allow(allowRemoveLast, $"\"{target.Name}\" is the last identity provider; without it nobody can log in", nameof(allowRemoveLast));
        if (!allowRemoveLast)
        {
            var remaining = all.Where(p => p.Id != providerId).Select(p => p.Id).ToHashSet(StringComparer.Ordinal);
            var stranded = (await ListApplicationsAsync(accountId, ct).ConfigureAwait(false))
                .Where(a => a.AllowedIdps.Contains(providerId, StringComparer.Ordinal) && !a.AllowedIdps.Any(remaining.Contains)).Select(a => $"\"{a.Name}\"").ToList();
            if (stranded.Count > 0)
                P2.Allow(false, $"application(s) {string.Join(", ", stranded)} allow only identity provider \"{target.Name}\"; without it nobody can log in there", nameof(allowRemoveLast));
        }
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
        if (body.ContainsKey("session_duration") && ZT.Longer(current.SessionDuration, c.SessionDuration))
            notes.Add(("allowLoosen", $"longer Access sessions ({current.SessionDuration ?? "default"} → {c.SessionDuration})"));
        Str("warp_auth_session_duration", c.WarpAuthSessionDuration, current.WarpAuthSessionDuration);
        if (body.ContainsKey("warp_auth_session_duration") && ZT.Longer(current.WarpAuthSessionDuration, c.WarpAuthSessionDuration))
            notes.Add(("allowLoosen", $"longer WARP authentication sessions ({current.WarpAuthSessionDuration ?? "default"} → {c.WarpAuthSessionDuration})"));
        Bool("auto_redirect_to_identity", c.AutoRedirectToIdentity, current.AutoRedirectToIdentity);
        Bool("is_ui_read_only", c.IsUiReadOnly, current.IsUiReadOnly);
        if (body.ContainsKey("is_ui_read_only") && c.UiReadOnlyToggleReason is { } reason) body["ui_read_only_toggle_reason"] = reason;
        if (body["is_ui_read_only"] is { } ro && !ro.GetValue<bool>())
            notes.Add(("allowLoosen", "turning off \"UI read-only\" lets the dashboard change what is managed through the API"));
        Bool("allow_authenticate_via_warp", c.AllowAuthenticateViaWarp, current.AllowAuthenticateViaWarp);
        if (body["allow_authenticate_via_warp"] is { } viaWarp && viaWarp.GetValue<bool>())
            notes.Add(("allowLoosen", "a WARP session alone would log users into Access applications"));
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
        var everyone = AccessPolicyRisk.AdmitsEveryone("allow", g.Include, g.Require ?? []);
        if (everyone && (current is null || !AccessPolicyRisk.AdmitsEveryone("allow", current.Include, current.Require)))
            P2.Allow(allowLoosen, $"group \"{g.Name}\" includes everyone", nameof(allowLoosen));
        if (current is not null && AccessPolicyRisk.Loosening(new("allow", current.Include, current.Exclude, current.Require), new("allow", g.Include, g.Exclude ?? [], g.Require ?? [])) is { } why)
            P2.Allow(allowLoosen, $"the change loosens group \"{current.Name}\": {why}", nameof(allowLoosen));
        return new JsonObject { ["name"] = g.Name, ["include"] = Rules(g.Include), ["exclude"] = Rules(g.Exclude ?? []), ["require"] = Rules(g.Require ?? []) };
    }

    private static JsonArray Rules(IEnumerable<JsonElement> rules) => new(rules.Select(r => P1.Node(r)).ToArray());
}

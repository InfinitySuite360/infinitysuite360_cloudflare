using System.Text.Json;
using System.Text.Json.Nodes;
using InfinitySuite360.Cloudflare.Http;

namespace InfinitySuite360.Cloudflare.Resources;

/// <summary>A Split Tunnel entry: an address range or a host name.</summary>
public sealed class SplitTunnelEntry : CloudflareModel
{
    public string? Address { get; init; }
    public string? Host { get; init; }
    public string? Description { get; init; }

    public static SplitTunnelEntry ForAddress(string cidr, string? description = null) => new() { Address = ResourceKit.Cidr(cidr, nameof(cidr)).Cidr, Description = description };
    public static SplitTunnelEntry ForHost(string host, string? description = null) => new() { Host = ResourceKit.Hostname(host, nameof(host), allowWildcard: true), Description = description };

    internal string Key => (Address ?? Host ?? "").ToLowerInvariant();
}

/// <summary>A WARP device settings profile (the default profile has no <see cref="PolicyId"/> match and applies to every device).</summary>
public sealed class DeviceProfile : CloudflareModel
{
    public string? PolicyId { get; init; }
    public string? Name { get; init; }
    public string? Description { get; init; }
    /// <summary>Wirefilter expression that selects the devices, for example <c>identity.email == "a@example.com"</c>.</summary>
    public string? Match { get; init; }
    public double? Precedence { get; init; }
    public bool Default { get; init; }
    public bool? Enabled { get; init; }
    /// <summary>The user cannot switch WARP off.</summary>
    public bool? SwitchLocked { get; init; }
    public bool? AllowModeSwitch { get; init; }
    public bool? AllowedToLeave { get; init; }
    public bool? AllowUpdates { get; init; }
    /// <summary>Minutes after which WARP reconnects by itself (0 = never).</summary>
    public double? AutoConnect { get; init; }
    public double? CaptivePortal { get; init; }
    public bool? DisableAutoFallback { get; init; }
    public bool? ExcludeOfficeIps { get; init; }
    public string? TunnelProtocol { get; init; }
    public string? SupportUrl { get; init; }
    public JsonElement? ServiceModeV2 { get; init; }
    public List<SplitTunnelEntry> Exclude { get; init; } = [];
    public List<SplitTunnelEntry> Include { get; init; } = [];
}

/// <summary>Settings of a device profile; only set fields are sent. Loosening values need <c>allowLoosen</c>.</summary>
public sealed class DeviceProfileSettings
{
    /// <summary>False lets users switch WARP off (loosening).</summary>
    public bool? SwitchLocked { get; init; }
    /// <summary>True lets users change the mode, for example away from Gateway with WARP (loosening).</summary>
    public bool? AllowModeSwitch { get; init; }
    /// <summary>True lets users leave the organization (loosening).</summary>
    public bool? AllowedToLeave { get; init; }
    public bool? AllowUpdates { get; init; }
    /// <summary>Minutes until WARP reconnects by itself; 0 (never) is loosening.</summary>
    public int? AutoConnect { get; init; }
    public int? CaptivePortal { get; init; }
    public bool? DisableAutoFallback { get; init; }
    public bool? ExcludeOfficeIps { get; init; }
    public string? SupportUrl { get; init; }
    public string? Description { get; init; }
}

/// <summary>A new custom device profile.</summary>
public sealed class DeviceProfileInput
{
    public required string Name { get; init; }
    /// <summary>Devices this profile applies to; an empty or catch-all match needs <c>allowBroadProfile</c>.</summary>
    public required string Match { get; init; }
    public required int Precedence { get; init; }
    public bool Enabled { get; init; } = true;
    public DeviceProfileSettings? Settings { get; init; }
}

/// <summary>A device posture rule (OS version, disk encryption, firewall, client certificate, third-party EDR …).</summary>
public sealed class DevicePostureRule : CloudflareModel
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Type { get; init; } = "";
    public string? Description { get; init; }
    public string? Schedule { get; init; }
    public string? Expiration { get; init; }
    public JsonElement? Input { get; init; }
    public JsonElement? Match { get; init; }
}

/// <summary>A new or changed posture rule.</summary>
public sealed class DevicePostureRuleInput
{
    public required string Name { get; init; }
    /// <summary>For example "os_version", "disk_encryption", "firewall", "file", "application", "client_certificate_v2", "warp", "gateway".</summary>
    public required string Type { get; init; }
    public JsonObject? Input { get; init; }
    /// <summary>Platforms, for example <c>[{"platform":"windows"}]</c>.</summary>
    public JsonArray? Match { get; init; }
    public string? Description { get; init; }
    public string? Schedule { get; init; }
}

/// <summary>A physical device with the Cloudflare One (WARP) client. Read-only; contains personal data (user, hardware): never copy it into logs or previews.</summary>
public sealed class ZeroTrustDevice : CloudflareModel
{
    public string Id { get; init; } = "";
    public string? Name { get; init; }
    public string? DeviceType { get; init; }
    public string? Model { get; init; }
    public string? Manufacturer { get; init; }
    public string? OsVersion { get; init; }
    public string? ClientVersion { get; init; }
    public int? ActiveRegistrations { get; init; }
    public DateTimeOffset? LastSeenAt { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public JsonElement? LastSeenUser { get; init; }
}

/// <summary>
/// WARP / devices: device settings profiles (default and custom), Split Tunnel, fallback domains, posture rules, devices (read-only) and registration
/// revocation. Endpoints from cloudflare/api-schemas@650bd71 (<c>devices-*</c>, <c>device-posture-rules-*</c>, <c>list-devices</c>, <c>revoke-registrations</c>),
/// retrieved 17.11.2026.
/// </summary>
/// <remarks>
/// <para>Every change of the default profile reaches every device and needs <c>allowBroadProfile</c>, as does a custom profile whose match selects all devices.
/// Loosening a profile (WARP can be switched off, the mode changed or the organization left, no auto-reconnect, new Split Tunnel exclusions that bypass
/// Gateway) needs <c>allowLoosen</c>; removing Split Tunnel exclusions can cut local networks off and needs <c>allowDisconnect</c>.</para>
/// <para>Posture rules used by Access policies, groups or Gateway rules are not changed or deleted without <c>allowInUse</c> (fresh read, fail-closed).</para>
/// <para>Previews of device operations contain counts only, never device ids, user names, e-mail addresses or hardware data.</para>
/// </remarks>
public sealed class DevicesClient(ICloudflareApiConnection api) : CloudflareResourceClient(api)
{
    // ------------------------------------------------------------------ profiles

    public Task<DeviceProfile> GetDefaultProfileAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.SendSecretFreeAsync<DeviceProfile>(Api, HttpMethod.Get, AccountPath(accountId, "devices", "policy"), null, ct);

    public Task<List<DeviceProfile>> ListProfilesAsync(string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.GetSecretFreeListAsync<DeviceProfile>(Api, AccountPath(accountId, "devices", "policies"), ct);

    public Task<DeviceProfile> GetProfileAsync(string policyId, string? accountId = null, CancellationToken ct = default) =>
        ResourceKit.SendSecretFreeAsync<DeviceProfile>(Api, HttpMethod.Get, AccountPath(accountId, "devices", "policy", ResourceKit.Required(policyId, nameof(policyId))), null, ct);

    /// <summary>Plan of a default profile change (reads the profile; sends no write).</summary>
    public async Task<CloudflareChangePreview> PreviewUpdateDefaultProfileAsync(DeviceProfileSettings settings, string? accountId = null, CancellationToken ct = default)
    {
        var current = await GetDefaultProfileAsync(accountId, ct).ConfigureAwait(false);
        var (body, loosening) = SettingsBody(current, settings);
        return new("PATCH", AccountPath(accountId, "devices", "policy"), body,
            $"Change {ResourceKit.Join(body.Select(p => p.Key))} of the default device profile (applies to every device)." + (loosening.Count > 0 ? $" WARNING: loosens ({string.Join("; ", loosening)})." : ""));
    }

    /// <summary>Changes the default profile (PATCH, only fields that differ from a fresh read). Always needs <paramref name="allowBroadProfile"/>; loosening needs <paramref name="allowLoosen"/>.</summary>
    public async Task<(DeviceProfile Profile, bool Changed)> UpdateDefaultProfileAsync(DeviceProfileSettings settings, bool allowBroadProfile = false, bool allowLoosen = false,
        string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "devices", "policy");
        EnsureWritable(HttpMethod.Patch, path);
        ResourceKit.Allow(allowBroadProfile, "the default device profile applies to every device", nameof(allowBroadProfile));
        var current = await GetDefaultProfileAsync(accountId, ct).ConfigureAwait(false);
        var (body, loosening) = SettingsBody(current, settings);
        if (loosening.Count > 0) ResourceKit.Allow(allowLoosen, $"the change loosens the default profile: {string.Join("; ", loosening)}", nameof(allowLoosen));
        if (body.Count == 0) return (current, false);
        return (await ResourceKit.SendSecretFreeAsync<DeviceProfile>(Api, HttpMethod.Patch, path, body, ct).ConfigureAwait(false), true);
    }

    public CloudflareChangePreview PreviewEnsureProfile(DeviceProfileInput profile, bool allowBroadProfile = false, string? accountId = null)
    {
        var (body, loosening) = ProfileBody(profile, allowBroadProfile);
        return new("POST", AccountPath(accountId, "devices", "policy"), body,
            $"Create device profile \"{profile.Name}\" (precedence {profile.Precedence})." + (loosening.Count > 0 ? $" WARNING: loosens ({string.Join("; ", loosening)}; needs allowLoosen)." : ""));
    }

    /// <summary>
    /// Returns the custom profile with this name or creates it; a match that selects all devices needs <paramref name="allowBroadProfile"/>. An existing
    /// profile is not changed. M2 (0.8.1): loosening settings in the new profile (WARP can be switched off, mode switch, leaving, self-updates, no
    /// auto-reconnect, local fallback, office IPs excluded) need <paramref name="allowLoosen"/>, as in <see cref="UpdateProfileAsync"/>.
    /// </summary>
    public async Task<(DeviceProfile Profile, bool Created)> EnsureProfileAsync(DeviceProfileInput profile, bool allowBroadProfile = false, string? accountId = null,
        bool allowLoosen = false, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "devices", "policy");
        EnsureWritable(HttpMethod.Post, path);
        var (body, loosening) = ProfileBody(profile, allowBroadProfile);
        if (loosening.Count > 0) ResourceKit.Allow(allowLoosen, $"device profile \"{profile.Name}\" would be created loose: {string.Join("; ", loosening)}", nameof(allowLoosen));
        var existing = (await ListProfilesAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(p => !p.Default && p.Name == profile.Name);
        if (existing is not null) return (existing, false);
        return (await ResourceKit.SendSecretFreeAsync<DeviceProfile>(Api, HttpMethod.Post, path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>
    /// Changes a custom profile after a fresh read (PATCH, only differing fields). A profile whose match selects all devices, or a new match that does, needs
    /// <paramref name="allowBroadProfile"/>; loosening needs <paramref name="allowLoosen"/>. M2 (0.8.1): changing the match moves devices into or out of
    /// this profile (out of it they fall back to looser profiles), so it counts as loosening.
    /// </summary>
    public async Task<(DeviceProfile Profile, bool Changed)> UpdateProfileAsync(string policyId, DeviceProfileSettings settings, string? match = null, bool allowBroadProfile = false,
        bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "devices", "policy", ResourceKit.Required(policyId, nameof(policyId)));
        EnsureWritable(HttpMethod.Patch, path);
        var current = await GetProfileAsync(policyId, accountId, ct).ConfigureAwait(false);
        if (current.Default || IsBroadMatch(current.Match) || (match is not null && IsBroadMatch(match)))
            ResourceKit.Allow(allowBroadProfile, $"device profile \"{current.Name}\" applies to every device", nameof(allowBroadProfile));
        var (body, loosening) = SettingsBody(current, settings);
        if (match is not null && match.Trim() != (current.Match ?? "").Trim())
        {
            body["match"] = match;
            loosening.Add($"the match changes which devices use the profile ({current.Match} → {match})");
        }
        if (loosening.Count > 0) ResourceKit.Allow(allowLoosen, $"the change loosens device profile \"{current.Name}\": {string.Join("; ", loosening)}", nameof(allowLoosen));
        if (body.Count == 0) return (current, false);
        return (await ResourceKit.SendSecretFreeAsync<DeviceProfile>(Api, HttpMethod.Patch, path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>Deletes a custom profile; its devices fall back to the default profile, so this always needs <paramref name="allowDelete"/>. False when it did not exist.</summary>
    public async Task<bool> RemoveProfileAsync(string policyId, bool allowDelete = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "devices", "policy", ResourceKit.Required(policyId, nameof(policyId)));
        EnsureWritable(HttpMethod.Delete, path);
        ResourceKit.Allow(allowDelete, "deleting a device profile moves its devices to the default profile", nameof(allowDelete));
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ split tunnel, fallback domains

    public async Task<List<SplitTunnelEntry>> GetSplitTunnelExcludeAsync(string? policyId = null, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<SplitTunnelEntry>>(ProfilePath(policyId, accountId, "exclude"), ct).ConfigureAwait(false) ?? [];

    public async Task<List<SplitTunnelEntry>> GetSplitTunnelIncludeAsync(string? policyId = null, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<SplitTunnelEntry>>(ProfilePath(policyId, accountId, "include"), ct).ConfigureAwait(false) ?? [];

    public async Task<List<JsonElement>> GetFallbackDomainsAsync(string? policyId = null, string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<JsonElement>>(ProfilePath(policyId, accountId, "fallback_domains"), ct).ConfigureAwait(false) ?? [];

    /// <summary>Plan of a Split Tunnel exclude list (reads the current list; sends no write).</summary>
    public async Task<CloudflareChangePreview> PreviewSetSplitTunnelExcludeAsync(IEnumerable<SplitTunnelEntry> entries, string? policyId = null, string? accountId = null, CancellationToken ct = default)
    {
        var next = CheckEntries(entries);
        var current = await GetSplitTunnelExcludeAsync(policyId, accountId, ct).ConfigureAwait(false);
        var (added, removed) = EntryDiff(current, next);
        return new("PUT", ProfilePath(policyId, accountId, "exclude"), EntriesBody(next),
            $"Set the Split Tunnel exclude list of the {(policyId is null ? "default profile" : $"profile {policyId}")}: {added.Count} added, {removed.Count} removed."
            + (added.Count > 0 ? " WARNING: excluded traffic bypasses Gateway." : ""));
    }

    /// <summary>
    /// Replaces the Split Tunnel exclude list of a profile (PUT) after a fresh read. Excluded traffic bypasses Gateway: new exclusions need
    /// <paramref name="allowLoosen"/>; removed ones can cut off local networks and need <paramref name="allowDisconnect"/>; the default profile
    /// (<paramref name="policyId"/> null) needs <paramref name="allowBroadProfile"/>. Written only on change. M3 (0.8.1): an exclusion that covers a large part
    /// of the address space (IPv4 shorter than /8, IPv6 shorter than /16, including 0.0.0.0/0 and ::/0) takes almost all traffic out of WARP and needs
    /// <paramref name="allowBroadRoute"/>; the profile is read first and a profile in Include mode (only the include list is in use) is refused, because an
    /// exclude list there would not do what the caller expects.
    /// </summary>
    public async Task<(List<SplitTunnelEntry> Entries, bool Changed)> SetSplitTunnelExcludeAsync(IEnumerable<SplitTunnelEntry> entries, string? policyId = null, bool allowBroadProfile = false,
        bool allowLoosen = false, bool allowDisconnect = false, string? accountId = null, bool allowBroadRoute = false, CancellationToken ct = default)
    {
        var path = ProfilePath(policyId, accountId, "exclude");
        EnsureWritable(HttpMethod.Put, path);
        var next = CheckEntries(entries);
        if (policyId is null) ResourceKit.Allow(allowBroadProfile, "the default device profile applies to every device", nameof(allowBroadProfile));
        var broad = next.Where(e => e.Address is not null && ResourceKit.IsBroadCidr(e.Address)).Select(e => e.Address!).ToList();
        if (broad.Count > 0) ResourceKit.Allow(allowBroadRoute, $"excluding {ResourceKit.Join(broad)} takes almost all traffic out of WARP and Gateway", nameof(allowBroadRoute));
        var profile = policyId is null ? await GetDefaultProfileAsync(accountId, ct).ConfigureAwait(false) : await GetProfileAsync(policyId, accountId, ct).ConfigureAwait(false);
        if (profile.Include.Count > 0 && profile.Exclude.Count == 0)
            throw new InvalidOperationException($"Refused: device profile \"{profile.Name ?? policyId ?? "default"}\" uses Split Tunnel Include mode ({ResourceKit.Plural(profile.Include.Count, "include entry", "include entries")}); an exclude list does not apply there. Change the mode deliberately in the dashboard or through the OpenApi client.");
        var current = await GetSplitTunnelExcludeAsync(policyId, accountId, ct).ConfigureAwait(false);
        var (added, removed) = EntryDiff(current, next);
        if (added.Count > 0) ResourceKit.Allow(allowLoosen, $"excluding {ResourceKit.Join(added)} lets that traffic bypass Gateway", nameof(allowLoosen));
        if (removed.Count > 0) ResourceKit.Allow(allowDisconnect, $"no longer excluding {ResourceKit.Join(removed)} sends it through WARP and can cut off local networks", nameof(allowDisconnect));
        if (added.Count + removed.Count == 0) return (current, false);
        return (await Api.PutAsync<List<SplitTunnelEntry>>(path, EntriesBody(next), ct).ConfigureAwait(false) ?? next, true);
    }

    private string ProfilePath(string? policyId, string? accountId, string leaf) =>
        policyId is null ? AccountPath(accountId, "devices", "policy", leaf) : AccountPath(accountId, "devices", "policy", ResourceKit.Required(policyId, nameof(policyId)), leaf);

    private static List<SplitTunnelEntry> CheckEntries(IEnumerable<SplitTunnelEntry> entries)
    {
        var list = new List<SplitTunnelEntry>();
        foreach (var e in entries)
        {
            if ((e.Address is null) == (e.Host is null)) throw new ArgumentException("Each entry has either an address or a host.", nameof(entries));
            list.Add(e.Address is not null ? SplitTunnelEntry.ForAddress(e.Address, e.Description) : SplitTunnelEntry.ForHost(e.Host!, e.Description));
        }
        if (list.Select(e => e.Key).Distinct().Count() != list.Count) throw new ArgumentException("Duplicate entries.", nameof(entries));
        return list;
    }

    private static (List<string> Added, List<string> Removed) EntryDiff(IEnumerable<SplitTunnelEntry> current, IEnumerable<SplitTunnelEntry> next)
    {
        var before = current.Select(e => e.Key).ToHashSet();
        var after = next.Select(e => e.Key).ToHashSet();
        return (after.Where(k => !before.Contains(k)).ToList(), before.Where(k => !after.Contains(k)).ToList());
    }

    private static JsonArray EntriesBody(IEnumerable<SplitTunnelEntry> entries) =>
        new(entries.Select(e =>
        {
            var o = new JsonObject();
            if (e.Address is not null) o["address"] = e.Address;
            if (e.Host is not null) o["host"] = e.Host;
            if (e.Description is not null) o["description"] = e.Description;
            return (JsonNode?)o;
        }).ToArray());

    /// <summary>
    /// A match that selects every device: empty, a tautology (<see cref="ResourceKit.MatchesAll"/>: <c>true</c>, <c>any</c>, <c>1 == 1</c>, <c>identity.email matches ".*"</c>,
    /// <c>identity.email ne ""</c>, <c>os.name in {…}</c> with every platform, also behind a top-level <c>or</c>). Syntactic (M2, 0.8.1); read the preview.
    /// </summary>
    private static bool IsBroadMatch(string? match) => ResourceKit.MatchesAll(match);

    private static (JsonObject Body, List<string> Loosening) ProfileBody(DeviceProfileInput p, bool allowBroadProfile)
    {
        ResourceKit.Required(p.Name, nameof(p), 100);
        if (IsBroadMatch(p.Match)) ResourceKit.Allow(allowBroadProfile, $"device profile \"{p.Name}\" would apply to every device", nameof(allowBroadProfile));
        if (p.Precedence is < 1 or > 10000) throw new ArgumentOutOfRangeException(nameof(p), "Precedence 1 to 10000.");
        var (settings, loosening) = SettingsBody(new DeviceProfile(), p.Settings ?? new DeviceProfileSettings());
        settings["name"] = p.Name;
        settings["match"] = p.Match;
        settings["precedence"] = p.Precedence;
        settings["enabled"] = p.Enabled;
        return (settings, loosening);
    }

    private static (JsonObject Body, List<string> Loosening) SettingsBody(DeviceProfile current, DeviceProfileSettings s)
    {
        var body = new JsonObject();
        var loosening = new List<string>();
        void B(string name, bool? next, bool? now, bool looseWhen, string what)
        {
            if (next is not { } n || n == now) return;
            body[name] = n;
            if (n == looseWhen) loosening.Add(what);
        }
        B("switch_locked", s.SwitchLocked, current.SwitchLocked, false, "users can switch WARP off");
        B("allow_mode_switch", s.AllowModeSwitch, current.AllowModeSwitch, true, "users can change the WARP mode");
        B("allowed_to_leave", s.AllowedToLeave, current.AllowedToLeave, true, "users can leave the organization");
        B("allow_updates", s.AllowUpdates, current.AllowUpdates, true, "users can update the client themselves");
        B("disable_auto_fallback", s.DisableAutoFallback, current.DisableAutoFallback, false, "WARP falls back to the local resolver");
        B("exclude_office_ips", s.ExcludeOfficeIps, current.ExcludeOfficeIps, true, "office IPs bypass WARP");
        if (s.AutoConnect is { } ac && ac != (int?)current.AutoConnect)
        {
            if (ac is < 0 or > 1440) throw new ArgumentOutOfRangeException(nameof(s), "AutoConnect 0 to 1440 minutes.");
            body["auto_connect"] = ac;
            if (ac == 0) loosening.Add("WARP does not reconnect by itself");
        }
        if (s.CaptivePortal is { } cp && cp != (int?)current.CaptivePortal)
        {
            if (cp is < 0 or > 3600) throw new ArgumentOutOfRangeException(nameof(s), "CaptivePortal 0 to 3600 seconds.");
            body["captive_portal"] = cp;
        }
        if (s.SupportUrl is { } url && url != current.SupportUrl) body["support_url"] = url;
        if (s.Description is { } d && d != current.Description) body["description"] = d;
        return (body, loosening);
    }

    // ------------------------------------------------------------------ posture rules

    public async Task<List<DevicePostureRule>> ListPostureRulesAsync(string? accountId = null, CancellationToken ct = default) =>
        await Api.GetAsync<List<DevicePostureRule>>(AccountPath(accountId, "devices", "posture"), ct).ConfigureAwait(false) ?? [];

    public Task<DevicePostureRule> GetPostureRuleAsync(string ruleId, string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<DevicePostureRule>(AccountPath(accountId, "devices", "posture", ResourceKit.Required(ruleId, nameof(ruleId))), ct);

    public CloudflareChangePreview PreviewEnsurePostureRule(DevicePostureRuleInput rule, string? accountId = null) =>
        new("POST", AccountPath(accountId, "devices", "posture"), ResourceKit.Redact(PostureBody(rule)), $"Create {rule.Type} posture rule \"{rule.Name}\".");

    /// <summary>Returns the posture rule with this name or creates it; an existing rule is not changed. A new rule has no effect until a policy uses it.</summary>
    public async Task<(DevicePostureRule Rule, bool Created)> EnsurePostureRuleAsync(DevicePostureRuleInput rule, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "devices", "posture");
        EnsureWritable(HttpMethod.Post, path);
        var body = PostureBody(rule);
        var existing = (await ListPostureRulesAsync(accountId, ct).ConfigureAwait(false)).FirstOrDefault(r => r.Name == rule.Name);
        if (existing is not null) return (existing, false);
        return (await Api.PostAsync<DevicePostureRule>(path, body, ct).ConfigureAwait(false), true);
    }

    /// <summary>
    /// Replaces a posture rule (PUT) after a fresh read. A rule used by Access policies/groups/applications, Gateway rules or device profile matches needs
    /// <paramref name="allowInUse"/> (fresh read, fail-closed). L5 (0.8.1): written only on change (an unchanged rule returns the current one without a
    /// write or an in-use check), and members the input does not set (for example <c>expiration</c>) are kept.
    /// </summary>
    public async Task<DevicePostureRule> UpdatePostureRuleAsync(string ruleId, DevicePostureRuleInput rule, bool allowInUse = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "devices", "posture", ResourceKit.Required(ruleId, nameof(ruleId)));
        EnsureWritable(HttpMethod.Put, path);
        var body = PostureBody(rule);
        var raw = await ResourceKit.SecretFreeResultAsync(Api, HttpMethod.Get, path, null, ct).ConfigureAwait(false);
        if (ResourceKit.Covers(ResourceKit.Node(raw), body)) return ResourceKit.As<DevicePostureRule>(raw);
        await RefusePostureInUseAsync(ruleId, allowInUse, "changing", accountId, ct).ConfigureAwait(false);
        return await ResourceKit.SendSecretFreeAsync<DevicePostureRule>(Api, HttpMethod.Put, path, ResourceKit.Merge(raw, body, "id", "created_at", "updated_at"), ct).ConfigureAwait(false);
    }

    /// <summary>Deletes a posture rule (same in-use check as <see cref="UpdatePostureRuleAsync"/>). False when it did not exist.</summary>
    public async Task<bool> RemovePostureRuleAsync(string ruleId, bool allowInUse = false, string? accountId = null, CancellationToken ct = default)
    {
        var path = AccountPath(accountId, "devices", "posture", ResourceKit.Required(ruleId, nameof(ruleId)));
        EnsureWritable(HttpMethod.Delete, path);
        await RefusePostureInUseAsync(ruleId, allowInUse, "deleting", accountId, ct).ConfigureAwait(false);
        return await DeleteIfExistsAsync(path, null, ct).ConfigureAwait(false);
    }

    private async Task RefusePostureInUseAsync(string ruleId, bool allowInUse, string what, string? accountId, CancellationToken ct)
    {
        if (allowInUse) return;
        var access = new AccessClient(Api);
        var users = new List<string>();
        foreach (var p in await access.ListPoliciesAsync(accountId, ct).ConfigureAwait(false))
            if (ResourceKit.References(ToElement(new { p.Include, p.Exclude, p.Require }), "device_posture", "integration_uid", ruleId)) users.Add($"Access policy \"{p.Name}\"");
        foreach (var g in await access.ListGroupsAsync(accountId, ct).ConfigureAwait(false))
            if (ResourceKit.References(ToElement(new { g.Include, g.Exclude, g.Require }), "device_posture", "integration_uid", ruleId)) users.Add($"Access group \"{g.Name}\"");
        foreach (var a in await access.ListApplicationsAsync(accountId, ct).ConfigureAwait(false))
            if (a.Policies.Any(x => ResourceKit.References(x, "device_posture", "integration_uid", ruleId))) users.Add($"Access application \"{a.Name}\"");
        foreach (var r in await new ZeroTrustGatewayClient(Api).ListRulesAsync(null, accountId, ct).ConfigureAwait(false))
            if ((r.DevicePosture ?? "").Contains(ruleId, StringComparison.OrdinalIgnoreCase)) users.Add($"Gateway rule \"{r.Name}\"");
        // L5 (0.8.1): device profile matches can select devices by posture results as well.
        foreach (var p in await ListProfilesAsync(accountId, ct).ConfigureAwait(false))
            if ((p.Match ?? "").Contains(ruleId, StringComparison.OrdinalIgnoreCase)) users.Add($"device profile \"{p.Name}\"");
        if (users.Count > 0)
            throw new InvalidOperationException($"Refused: {what} posture rule {ruleId} changes who passes {string.Join(", ", users)}. Pass allowInUse: true deliberately.");
    }

    private static JsonObject PostureBody(DevicePostureRuleInput r)
    {
        ResourceKit.Required(r.Name, nameof(r), 255);
        ResourceKit.Required(r.Type, nameof(r), 64);
        var body = new JsonObject { ["name"] = r.Name, ["type"] = r.Type };
        if (r.Input is not null) body["input"] = r.Input.DeepClone();
        if (r.Match is not null) body["match"] = r.Match.DeepClone();
        if (r.Description is not null) body["description"] = r.Description;
        if (r.Schedule is not null) body["schedule"] = r.Schedule;
        return body;
    }

    // ------------------------------------------------------------------ devices

    /// <summary>Physical devices (cursor paging, <paramref name="maxItems"/> at most). Personal data: do not log.</summary>
    public async Task<List<ZeroTrustDevice>> ListDevicesAsync(string? search = null, int maxItems = 1000, string? accountId = null, CancellationToken ct = default)
    {
        var list = new List<ZeroTrustDevice>();
        await foreach (var d in Api.ListAllAsync<ZeroTrustDevice>(CloudflarePath.WithQuery(AccountPath(accountId, "devices", "physical-devices"), ("search", search)), 50, ct).ConfigureAwait(false))
        {
            list.Add(d);
            if (list.Count >= Math.Max(1, maxItems)) break;
        }
        return list;
    }

    public Task<JsonElement> GetSettingsAsync(string? accountId = null, CancellationToken ct = default) =>
        Api.GetAsync<JsonElement>(AccountPath(accountId, "devices", "settings"), ct);

    /// <summary>Plan of a revocation: the preview carries the number of registrations only (no ids, no user or device data).</summary>
    public CloudflareChangePreview PreviewRevokeRegistrations(IEnumerable<string> registrationIds, string? accountId = null) =>
        new("POST", AccountPath(accountId, "devices", "registrations", "revoke"), null, $"Revoke {ResourceKit.Plural(Ids(registrationIds).Count, "device registration", "device registrations")}.");

    /// <summary>Revokes device registrations (the devices lose access until re-enrolled); always needs <paramref name="allowDisconnect"/>.</summary>
    public async Task RevokeRegistrationsAsync(IEnumerable<string> registrationIds, bool allowDisconnect = false, string? accountId = null, CancellationToken ct = default)
    {
        var ids = Ids(registrationIds);
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "devices", "registrations", "revoke"), ids.Select(i => new KeyValuePair<string, string?>("id", i)));
        EnsureWritable(HttpMethod.Post, path);
        ResourceKit.Allow(allowDisconnect, $"revoking {ResourceKit.Plural(ids.Count, "registration", "registrations")} cuts those devices off", nameof(allowDisconnect));
        await Api.SendAsync<JsonElement>(HttpMethod.Post, path, null, ct).ConfigureAwait(false);
    }

    /// <summary>Restores revoked registrations (a device that was revoked for a reason gets access again); always needs <paramref name="allowLoosen"/>.</summary>
    public async Task UnrevokeRegistrationsAsync(IEnumerable<string> registrationIds, bool allowLoosen = false, string? accountId = null, CancellationToken ct = default)
    {
        var ids = Ids(registrationIds);
        var path = CloudflarePath.WithQuery(AccountPath(accountId, "devices", "registrations", "unrevoke"), ids.Select(i => new KeyValuePair<string, string?>("id", i)));
        EnsureWritable(HttpMethod.Post, path);
        ResourceKit.Allow(allowLoosen, $"un-revoking {ResourceKit.Plural(ids.Count, "registration", "registrations")} gives those devices access again", nameof(allowLoosen));
        await Api.SendAsync<JsonElement>(HttpMethod.Post, path, null, ct).ConfigureAwait(false);
    }

    private static List<string> Ids(IEnumerable<string> ids)
    {
        var list = ids.Select(i => ResourceKit.Required(i, nameof(ids), 64)).Distinct().ToList();
        if (list.Count is 0 or > 100) throw new ArgumentException("1 to 100 registration ids.", nameof(ids));
        return list;
    }
}

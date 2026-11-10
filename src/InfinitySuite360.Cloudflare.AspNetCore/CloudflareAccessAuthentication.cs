using System.Security.Claims;
using System.Text.Encodings.Web;
using InfinitySuite360.Cloudflare.AccessJwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace InfinitySuite360.Cloudflare.AspNetCore;

/// <summary>Settings of the authentication scheme.</summary>
public sealed class CloudflareAccessAuthenticationOptions : AuthenticationSchemeOptions
{
    public const string DefaultScheme = "CloudflareAccess";

    /// <summary>Claim types of the principal that is built from the token.</summary>
    public const string TypeClaim = "cf:type", CommonNameClaim = "cf:common_name", IdentityNonceClaim = "cf:identity_nonce", CountryClaim = "cf:country", GroupClaim = "cf:group";

    /// <summary>
    /// Also accept the token from the <c>CF_Authorization</c> cookie when the header is missing. Default: <c>false</c>. The token is checked the same way, but the header is what
    /// Cloudflare sets on every request that passed Access; a cookie is something a browser sends on its own.
    /// </summary>
    public bool AllowCookieFallback { get; set; }
}

/// <summary>
/// Authenticates requests by the token that Cloudflare Access signs (<c>Cf-Access-Jwt-Assertion</c>). No token: no result (anonymous). A token that fails the check: authentication failure,
/// logged with the reason; the caller only sees 401. Needs <c>AddCloudflareInfinitySuite360Core</c> or <c>AddCloudflareInfinitySuite360</c> (it provides the validator) and <c>Cloudflare:AccessJwt</c> settings.
/// </summary>
public sealed class CloudflareAccessAuthenticationHandler(IOptionsMonitor<CloudflareAccessAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<CloudflareAccessAuthenticationOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.Headers[CloudflareAccessJwtOptions.HeaderName].ToString();
        if (token.Length == 0 && Options.AllowCookieFallback) token = Request.Cookies[CloudflareAccessJwtOptions.CookieName] ?? "";
        if (token.Length == 0) return AuthenticateResult.NoResult();

        var validator = Context.RequestServices.GetService<ICloudflareAccessJwtValidator>()
                        ?? throw new InvalidOperationException("ICloudflareAccessJwtValidator is not registered: call AddCloudflareInfinitySuite360Core (or AddCloudflareInfinitySuite360) first.");
        var result = await validator.ValidateAsync(token, Context.RequestAborted).ConfigureAwait(false);
        if (!result.Ok)
        {
            Logger.LogWarning("Cloudflare Access token refused ({Failure}): {Message}", result.Failure, result.Message);
            return AuthenticateResult.Fail($"Cloudflare Access token refused ({result.Failure}).");
        }
        var principal = new ClaimsPrincipal(ToIdentity(result.Identity!, Scheme.Name));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    // The caller learns nothing beyond "401"; there is no redirect to a login page — Cloudflare Access is the login.
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    /// <summary>The claims of an identity: name identifier, e-mail, name (e-mail or service token), the Cloudflare values and one claim per group.</summary>
    public static ClaimsIdentity ToIdentity(CloudflareAccessIdentity id, string authenticationType)
    {
        var claims = new List<Claim> { new(ClaimTypes.NameIdentifier, id.Subject), new(ClaimTypes.Name, id.Email ?? id.CommonName ?? id.Subject) };
        void Add(string type, string? value) { if (!string.IsNullOrEmpty(value)) claims.Add(new Claim(type, value)); }
        Add(ClaimTypes.Email, id.Email);
        Add(CloudflareAccessAuthenticationOptions.CommonNameClaim, id.CommonName);
        Add(CloudflareAccessAuthenticationOptions.IdentityNonceClaim, id.IdentityNonce);
        Add(CloudflareAccessAuthenticationOptions.TypeClaim, id.Type);
        Add(CloudflareAccessAuthenticationOptions.CountryClaim, id.Country);
        foreach (var group in id.Groups) Add(CloudflareAccessAuthenticationOptions.GroupClaim, group);
        return new ClaimsIdentity(claims, authenticationType, ClaimTypes.Name, ClaimTypes.Role);
    }
}

public static class CloudflareAccessAuthenticationExtensions
{
    /// <summary>
    /// Adds the scheme <see cref="CloudflareAccessAuthenticationOptions.DefaultScheme"/>. Use it as the default scheme (<c>AddAuthentication(CloudflareAccessAuthenticationOptions.DefaultScheme)</c>)
    /// and protect endpoints with <c>[Authorize]</c> or <c>RequireAuthorization()</c>. Configure <c>Cloudflare:AccessJwt:TeamDomain</c> and <c>Audiences</c>.
    /// </summary>
    public static AuthenticationBuilder AddCloudflareAccess(this AuthenticationBuilder builder, Action<CloudflareAccessAuthenticationOptions>? configure = null) =>
        builder.AddCloudflareAccess(CloudflareAccessAuthenticationOptions.DefaultScheme, configure);

    public static AuthenticationBuilder AddCloudflareAccess(this AuthenticationBuilder builder, string scheme, Action<CloudflareAccessAuthenticationOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddScheme<CloudflareAccessAuthenticationOptions, CloudflareAccessAuthenticationHandler>(scheme, configure);
    }

    /// <summary>The Cloudflare Access values of the signed-in principal; <c>null</c> for anyone else.</summary>
    public static CloudflareAccessPrincipal? CloudflareAccess(this ClaimsPrincipal user) =>
        user.Identity?.IsAuthenticated == true && user.FindFirst(ClaimTypes.NameIdentifier) is { } sub
            ? new CloudflareAccessPrincipal(sub.Value, user.FindFirst(ClaimTypes.Email)?.Value, user.FindFirst(CloudflareAccessAuthenticationOptions.CommonNameClaim)?.Value,
                user.FindFirst(CloudflareAccessAuthenticationOptions.IdentityNonceClaim)?.Value, user.FindFirst(CloudflareAccessAuthenticationOptions.TypeClaim)?.Value,
                [.. user.FindAll(CloudflareAccessAuthenticationOptions.GroupClaim).Select(c => c.Value)])
            : null;
}

/// <summary>What the claims of a Cloudflare Access sign-in say.</summary>
public sealed record CloudflareAccessPrincipal(string Subject, string? Email, string? CommonName, string? IdentityNonce, string? Type, IReadOnlyList<string> Groups)
{
    /// <summary>A machine (service token) rather than a person.</summary>
    public bool IsServiceToken => CommonName is not null && Email is null;
}

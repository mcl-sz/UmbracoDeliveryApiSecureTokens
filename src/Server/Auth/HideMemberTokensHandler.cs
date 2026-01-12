using Microsoft.AspNetCore.DataProtection;
using OpenIddict.Server;
using OpenIddict.Validation;
using System.Diagnostics.CodeAnalysis;
using Umbraco.Cms.Api.Common.Security;
using Umbraco.Cms.Core;

namespace Server.Auth;

public class HideMemberTokensHandler
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyTokenResponseContext>,
        IOpenIddictServerHandler<OpenIddictServerEvents.ExtractTokenRequestContext>,
        IOpenIddictServerHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>,
        IOpenIddictValidationHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    private const string RedactedTokenValue = "[removed]";
    private const string AccessTokenCookieKey = "__Host-MemberAccessToken";
    private const string RefreshTokenCookieKey = "__Host-MemberRefreshToken";
    private const string CodeCookieKey = "__Host-MemberCode";


    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly RequestDelegate _next;

    public HideMemberTokensHandler(IHttpContextAccessor httpContextAccessor, IDataProtectionProvider dataProtectionProvider, RequestDelegate? next = null)
    {
        _httpContextAccessor = httpContextAccessor;
        _dataProtectionProvider = dataProtectionProvider;
        _next = next ?? (_ => Task.CompletedTask);
    }

    /// <summary>
    /// Intercept the UserInfo endpoint to change the accesstoken.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path == Paths.MemberApi.UserinfoEndpoint)
        {
            var authHeader = context.Request.Headers["Authorization"].ToString();

            if (!string.IsNullOrEmpty(authHeader) && authHeader == $"Bearer {RedactedTokenValue}")
            {
                if (TryGetCookie(AccessTokenCookieKey, out var accessToken))
                {
                    context.Request.Headers["Authorization"] = $"Bearer {accessToken}";
                }
            }
        }

        await _next(context);
    }

    /// <summary>
    /// This is invoked when PKCE codes are issued to the client.
    /// </summary>
    public ValueTask HandleAsync(OpenIddictServerEvents.ApplyAuthorizationResponseContext context)
    {
        if (context.Request?.ClientId is not Constants.OAuthClientIds.Member)
        {
            // Only ever handle the member client.
            return ValueTask.CompletedTask;
        }

        if (context.Response.Code is not null)
        {
            // move the PKCE code to a secure cookie, and redact it from the response.
            SetCookie(GetHttpContext(), CodeCookieKey, context.Response.Code);
            context.Response.Code = RedactedTokenValue;
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// This is invoked when tokens (access and refresh tokens) are issued to a client.
    /// </summary>
    public ValueTask HandleAsync(OpenIddictServerEvents.ApplyTokenResponseContext context)
    {
        if (context.Request?.ClientId is not Constants.OAuthClientIds.Member)
        {
            // Only ever handle the member client.
            return ValueTask.CompletedTask;
        }

        HttpContext httpContext = GetHttpContext();

        if (context.Response.AccessToken is not null)
        {
            // move the access token to a secure cookie, and redact it from the response.
            SetCookie(httpContext, AccessTokenCookieKey, context.Response.AccessToken);
            context.Response.AccessToken = RedactedTokenValue;
        }

        if (context.Response.RefreshToken is not null)
        {
            // move the refresh token to a secure cookie, and redact it from the response.
            SetCookie(httpContext, RefreshTokenCookieKey, context.Response.RefreshToken);
            context.Response.RefreshToken = RedactedTokenValue;
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// This is invoked when requesting new tokens.
    /// </summary>
    public ValueTask HandleAsync(OpenIddictServerEvents.ExtractTokenRequestContext context)
    {
        if (context.Request?.ClientId != Constants.OAuthClientIds.Member)
        {
            // Only ever handle the member client.
            return ValueTask.CompletedTask;
        }

        // Handle when the PKCE code is being exchanged for an access token. 
        if (context.Request.Code == RedactedTokenValue
            && TryGetCookie(CodeCookieKey, out var code))
        {
            context.Request.Code = code;
        }
        else
        {
            // PCKE codes should always be redacted. If we got here, someone might be trying to pass another PKCE
            // code. For security reasons, explicitly discard the code (if any) to be on the safe side.
            context.Request.Code = null;
        }

        // Handle when a refresh token is being exchanged for a new access token.
        if (context.Request.RefreshToken == RedactedTokenValue
            && TryGetCookie(RefreshTokenCookieKey, out var refreshToken))
        {
            context.Request.RefreshToken = refreshToken;
        }
        else
        {
            // Refresh tokens should always be redacted. If we got here, an old (but potentially still valid)
            // refresh token might have been sent to the token endpoint. For security reasons, explicitly discard
            // the token (if any) to be on the safe side.
            context.Request.RefreshToken = null;
        }

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// This is invoked when extracting the auth context for a client request.
    /// </summary>
    public ValueTask HandleAsync(OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        // For the member client, this only happens when an access token is sent to the API.
        if (context.AccessToken != RedactedTokenValue)
        {
            return ValueTask.CompletedTask;
        }

        if (TryGetCookie(AccessTokenCookieKey, out var accessToken))
        {
            context.AccessToken = accessToken;
        }

        return ValueTask.CompletedTask;
    }

    private HttpContext GetHttpContext()
        => _httpContextAccessor.GetRequiredHttpContext();

    private void SetCookie(HttpContext httpContext, string key, string value)
    {
        // Encrypt the token before passing it out as a token, just for added security.
        var cookieValue = Encrypt(value);

        // See cookie best practices here: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps#name-cookie-security
        var cookieOptions = new CookieOptions
        {
            // Prevent the client-side scripts from accessing the cookie.
            HttpOnly = true,

            // Since the cookie is sent to another host, SameSite cannot be applied according to best practice (strict).
            // If your web app runs on the same host as the server, set this to SameSiteMode.Strict.
            SameSite = SameSiteMode.None,

            // Strictly only use secure cookies.
            Secure = true,

            // Cookie path must be root for optimal security.
            Path = "/",

            // Mark the cookie as essential to the application, to enforce it despite any
            // data collection consent options. This aligns with how ASP.NET Core Identity
            // does when writing cookies for cookie authentication.
            IsEssential = true,
        };

        httpContext.Response.Cookies.Delete(key, cookieOptions);
        httpContext.Response.Cookies.Append(key, cookieValue, cookieOptions);
    }

    private bool TryGetCookie(string key, [NotNullWhen(true)] out string? value)
    {
        if (GetHttpContext().Request.Cookies.TryGetValue(key, out var cookieValue))
        {
            // Decrypt the cookie value to obtain the original token.
            value = Decrypt(cookieValue);
            return true;
        }

        value = null;
        return false;
    }

    private string Encrypt(string value)
        => CreateDataProtector().Protect(value);

    private string Decrypt(string value)
        => CreateDataProtector().Unprotect(value);

    private IDataProtector CreateDataProtector()
        => _dataProtectionProvider.CreateProtector(nameof(HideMemberTokensHandler));
}
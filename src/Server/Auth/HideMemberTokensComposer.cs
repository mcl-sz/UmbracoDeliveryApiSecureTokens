using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;
using Umbraco.Cms.Core.Composing;

namespace Server.Auth;

public class HideMemberTokensComposer : IComposer
{
    public void Compose(IUmbracoBuilder builder)
        => builder.Services
            .AddOpenIddict()
            .AddServer(options =>
            {
                options.AddEventHandler<OpenIddictServerEvents.ApplyTokenResponseContext>(configuration =>
                {
                    // Add a handler here to intercept the access token response.
                    // It should move the access and refresh tokens to cookies, and redact them from the response.
                    configuration
                        .UseSingletonHandler<HideMemberTokensHandler>()
                        .SetOrder(OpenIddictServerAspNetCoreHandlers.ProcessJsonResponse<OpenIddictServerEvents.ApplyTokenResponseContext>.Descriptor.Order - 1);
                });
                options.AddEventHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>(configuration =>
                {
                    // Add a handler here to intercept the PKCE code response.
                    // It should move the PKCE code to a cookie, and redact it from the response.
                    configuration
                        .UseSingletonHandler<HideMemberTokensHandler>()
                        .SetOrder(OpenIddictServerAspNetCoreHandlers.Authentication.ProcessQueryResponse.Descriptor.Order - 1);
                });
                options.AddEventHandler<OpenIddictServerEvents.ExtractTokenRequestContext>(configuration =>
                {
                    // Add a handler here to contextualize requests for the refresh token endpoint.
                    // It should read the refresh token from its cookie and apply it to the request context.
                    configuration
                        .UseSingletonHandler<HideMemberTokensHandler>()
                        .SetOrder(OpenIddictServerAspNetCoreHandlers.ExtractPostRequest<OpenIddictServerEvents.ExtractTokenRequestContext>.Descriptor.Order + 1);
                });
            })
            .AddValidation(options =>
            {
                options.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(configuration =>
                {
                    // Add a handler here to contextualize requests for protected resources.
                    // It should read the access token from its cookie and apply it to the authentication context.
                    configuration
                        .UseSingletonHandler<HideMemberTokensHandler>()
                        .SetOrder(OpenIddictValidationAspNetCoreHandlers.ExtractAccessTokenFromAuthorizationHeader.Descriptor.Order + 1);
                });
            });
}
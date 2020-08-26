using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Caching;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Authin.Api.Sdk.Model;
using Authin.Api.Sdk.Request;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Authin.Provider;

namespace Owin.Security.Providers.Authin
{
    public class AuthinAuthenticationHandler : AuthenticationHandler<AuthinAuthenticationOptions>
    {
        #region Private Field

        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        #endregion

        #region Public Methods

        public AuthinAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        #endregion

        #region Overridden Methods

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                var properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenResponse = await RequestToken(code);
                var accessToken = tokenResponse.AccessToken;
                var refreshToken = tokenResponse.RefreshToken;
                var idToken = tokenResponse.IdToken;

                var accessTokenClaims = ValidateToken(accessToken);
                var refreshTokenClaims = ValidateToken(idToken);
                var idTokenClaims = ValidateToken(idToken);

                if (accessTokenClaims == null || refreshTokenClaims == null || idTokenClaims == null)
                    return new AuthenticationTicket(null, properties);

                var context = new AuthinAuthenticatedContext(Context, accessToken, refreshToken, idToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };
                context = Options.ClaimsCallback.Invoke(context, idTokenClaims);

                if (!string.IsNullOrWhiteSpace(context.AccessToken))
                    context.Identity.AddClaim(new Claim("access_token", context.AccessToken, ClaimValueTypes.String,
                        Options.Issuer));
                if (!string.IsNullOrWhiteSpace(context.RefreshToken))
                    context.Identity.AddClaim(new Claim("refresh_token", context.RefreshToken, ClaimValueTypes.String,
                        Options.Issuer));
                if (!string.IsNullOrWhiteSpace(context.IdToken))
                    context.Identity.AddClaim(new Claim("id_token", context.IdToken, ClaimValueTypes.String,
                        Options.Issuer));

                context.Properties = properties;
                await Options.Provider.Authenticated(context);
                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
                throw;
            }
        }


        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null) return Task.FromResult<object>(null);

            var baseUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"] + Request.PathBase;
            var currentUri = baseUri + Request.Path + Request.QueryString;
            var redirectUri = baseUri + Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var state = Options.StateDataFormat.Protect(properties);

            var builder = AuthorizationCodeRequest.GetBuilder();
            var request = builder.SetClientId(Options.ClientId)
                .SetResponseType(Options.ResponseType)
                .SetRedirectUri(redirectUri)
                .AddScopes(Options.Scope)
                .SetState(state)
                .AddUserInfoClaims(Options.Claims.UserInfo)
                .AddIdTokenClaims(Options.Claims.IdToken)
                .Build();

            var authorizationRedirectUri = request.Execute().GetAwaiter().GetResult().AbsoluteUri;

            Response.Redirect(authorizationRedirectUri);

            return Task.FromResult<object>(null);
        }

        #endregion

        #region Private Methods

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;
            // TODO: error responses

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new AuthinReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType,
                    StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType,
                        grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }

                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }

            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }

        private async Task<TokenResponse> RequestToken(string code)
        {
            var requestPrefix = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
            var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

            var builder = TokenRequest.GetBuilder();
            var tokenRequest = builder.SetCode(code)
                .SetRedirectUri(redirectUri)
                .SetClientId(Options.ClientId)
                .SetClientSecret(Options.ClientSecret)
                .SetGrantType(Options.GrantType)
                .Build();

            var tokenResponse = await tokenRequest.Execute();

            return tokenResponse;
        }

        private ClaimsPrincipal ValidateToken(string accessToken, bool secondTime = false)
        {
            var validationParameters =
                new TokenValidationParameters
                {
                    ValidIssuer = Options.Issuer,
                    ValidAudiences = new[] {Options.ClientId},
                    ValidateLifetime = true,
                    RequireSignedTokens = true,
                    RequireExpirationTime = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    IssuerSigningKeyResolver = AuthinSigningKeyResolver
                };

            var handler = new JwtSecurityTokenHandler();

            try
            {
                SecurityToken validatedToken;
                return handler.ValidateToken(accessToken, validationParameters, out validatedToken);
            }
            catch (Exception e)
            {
                //clear cache in order to get new one
                var cache = MemoryCache.Default;
                cache.Remove("modulus");
                cache.Remove("exponent");

                if (!secondTime)
                    ValidateToken(accessToken, true);
                else
                    _logger.WriteError(e.Message);
            }

            return null;
        }

        private IEnumerable<SecurityKey> AuthinSigningKeyResolver(string token, SecurityToken securityToken, string kid,
            TokenValidationParameters validationParameters)
        {
            var cache = MemoryCache.Default;
            var cachedModulus = cache.Get("modulus") as string;
            var cachedExponent = cache.Get("exponent") as string;

            var securityKeys = new List<SecurityKey>();

            if (string.IsNullOrEmpty(cachedModulus) || string.IsNullOrEmpty(cachedExponent))
            {
                var builder = JwksRequest.GetBuilder();
                var jwksRequest = builder.Build();
                var rsaJwk = Task.Run(() => jwksRequest.Execute()).Result;

                //do caching
                cachedModulus = rsaJwk.Keys[0].Modulus;
                cachedExponent = rsaJwk.Keys[0].Exponent;
                var policy = new CacheItemPolicy();
                cache.Set("modulus", cachedModulus, policy);
                cache.Set("exponent", cachedExponent, policy);
            }

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = Base64UrlEncoder.DecodeBytes(cachedModulus),
                Exponent = Base64UrlEncoder.DecodeBytes(cachedExponent)
            });

            securityKeys.Add(new RsaSecurityKey(rsa));


            return securityKeys;
        }

        #endregion
    }
}
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Authin.Provider;

namespace Owin.Security.Providers.Authin
{
    public class AuthinAuthenticationOptions : AuthenticationOptions
    {
        private const string AuthorizationEndPoint = "http://demo.authin.ir/openidauthorize";
        private const string TokenEndpoint = "http://demo.authin.ir/api/v1/oauth/token";
        private const string UserInfoEndpoint = "http://demo.authin.ir/api/v1/oauth/userinfo";
        private const string JwksEndpoint = "http://demo.authin.ir/api/v1/keys";

        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }
        public TimeSpan BackchannelTimeout { get; set; }
        public PathString CallbackPath { get; set; }
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string ResponseType { get; set; }
        public string GrantType { get; set; }
        public string Issuer { get; set; }
        public Claims Claims { get; set; }
        public AuthinAuthenticationEndpoints Endpoints { get; set; }
        public IAuthinAuthenticationProvider Provider { get; set; }
        public string SignInAsAuthenticationType { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        private IList<string> _scopes;
        public IList<string> Scope
        {
            get { return _scopes; }
            set
            {
                _scopes = value;
                if(_scopes.Contains("openid"))
                    _scopes.Add("openid");
            }
        }

        public delegate AuthinAuthenticatedContext ContextDelegate(AuthinAuthenticatedContext context, ClaimsPrincipal claims);
        public ContextDelegate ClaimsCallback { get; set; }

        public AuthinAuthenticationOptions()
            : base("Authin")
        {
            Caption = "Authin";
            CallbackPath = new PathString("/signin-authin");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "openid"
            };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new AuthinAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint,
                UserInfoEndpoint = UserInfoEndpoint,
                JwksEndpoint = JwksEndpoint
            };
        }

    }

    public class AuthinAuthenticationEndpoints
    {
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string UserInfoEndpoint { get; set; }
        public string JwksEndpoint { get; set; }
    }

    public class Claims
    {
        public List<string> UserInfo { get; set; }
        public List<string> IdToken{ get; set; }
    }
}
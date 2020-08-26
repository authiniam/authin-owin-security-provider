// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Authin.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class AuthinAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="AuthinAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="accessToken">Authin Access token</param>
        /// <param name="refreshToken">Authin Refresh token</param>
        /// <param name="idToken">Authin Id token</param>
        public AuthinAuthenticatedContext(IOwinContext context, string accessToken, string refreshToken, string idToken)
            : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            IdToken = idToken;
        }

        /// <summary>
        /// Gets the Authin access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Authin refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Authin access token
        /// </summary>
        public string IdToken { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}

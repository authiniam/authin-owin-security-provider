using System;
using Owin;

namespace Owin.Security.Providers.Authin
{
    public static class AuthinAuthenticationExtensions
    {
        public static IAppBuilder UseAuthinAuthentication(this IAppBuilder app,
            AuthinAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(AuthinAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseAuthinAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseAuthinAuthentication(new AuthinAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}
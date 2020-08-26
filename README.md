**<h1 dir="rtl">authin-owin-security-provider</h1>**
<p dir="rtl">Authin Owin Security Provider</p>

<h2 dir="rtl">استفاده از Owin.Security.Provider.Authin در ASP.NET MVC</h2>
<br/>

**<p dir="rtl">1. کتابخانه <code>Authin.Api.Sdk.dll</code> که در آدرس <a href="https://github.com/authiniam/authin-net/tree/master/Authin.Api.Sdk/ReleaseFiles">Authin.Api.Sdk/ReleaseFiles/</a> وجود دارد را به رفرنس‌های پروژه خود اضافه کنید.</p>**
<br/>

**<p dir="rtl">2.  کتابخانه <code>Owin.Security.Provider.Authin</code> که در آدرس <a href="https://github.com/authiniam/authin-owin-security-provider/tree/master/Owin.Security.Providers.Authin/ReleaseFiles">Owin.Security.Providers.Authin/ReleaseFiles/</a> وجود دارد را نیز به رفرنس‌های پروژه خود اضافه کنید.</p>**
<br/>

**<p dir="rtl">3. <code>NuGet pacakge</code>های زیر را بر روی پروژه مقصد نصب کنید:</p>**

```
Install-Package Newtonsoft.Json -Version 10.0.1
Install-Package Microsoft.IdentityModel.Tokens
Install-Package System.IdentityModel.Tokens.Jwt
```
<br/>

**<p dir="rtl">4. مقادیر زیر را به <code>\<appSettings\></code> در <code>Web.config</code> اضافه کنید.</p>**

``` xml
<add key="BaseUrl" value="authin_url" /> 
<!-- example: https://demo.authin.ir -->
<add key="RedirectUri" value="redirect_uri" /> 
<!-- example: https://lms.authin.ir/callback -->
<add key="ClientId" value="provided_clinet_id" /> 
<!-- example: xxxxxxxx-xxxx-47d6-80a5-fdc20dcae13f -->
<add key="ClientSecret" value="provided_client_secret" /> 
<!-- example: xxxxxxxxxxxxxxxxxxxx631f0f63f476f1231f533c924cf36a020d2a1bd12596 -->
```
<br/>

**<p dir="rtl">5. <code>AuthinAuthentication</code> را به انتهای متد <code>ConfigureAuth</code> از کلاس <code>Startup.Auth.cs</code> به شکل زیر اضافه کنید:</p>**

``` csharp
app.UseAuthinAuthentication(new AuthinAuthenticationOptions
{
    ClientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"],
    ClientSecret = System.Configuration.ConfigurationManager.AppSettings["ClientSecret"],
    ResponseType = "code",
    GrantType = "authorization_code",
    Issuer = "https://www.authin.ir",
    Scope = { "email", "profile" },
    Endpoints = new AuthinAuthenticationEndpoints
    {
        AuthorizationEndpoint = System.Configuration.ConfigurationManager.AppSettings["BaseUrl"] +
                                "/openidauthorize",
        TokenEndpoint = System.Configuration.ConfigurationManager.AppSettings["BaseUrl"] +
                        "/api/v1/oauth/token",
        UserInfoEndpoint = System.Configuration.ConfigurationManager.AppSettings["BaseUrl"] +
                            "/api/v1/oauth/userinfo",
        JwksEndpoint = System.Configuration.ConfigurationManager.AppSettings["BaseUrl"] + "/api/v1/keys"
    },
    Claims = new Claims
    {
        UserInfo = new List<string>(),
        IdToken = new List<string> { "email" }
    },

    ClaimsCallback = (context, idTokenClaims) =>
    {
        if (idTokenClaims.Claims.Any(c => c.Type.Equals(ClaimTypes.NameIdentifier)))
            context.Identity.AddClaim(idTokenClaims.Claims.First(c =>
                c.Type.Equals(ClaimTypes.NameIdentifier)));

        return context;
    }
});
```
<br/>

<blockquote dir="rtl">در قسمت <code>ClaimsCallback</code> تمام <code>claim</code>های استخراج شده از <code>id_token</code> ارائه شده اند که بنا به نیاز خود می‌توانید موارد دیگر را به <code>claim</code>های  <code>context</code> اضافه کنید. </blockquote>

<br/>

<blockquote dir="rtl">پس از احراز هویت کاربر متد <code>ExternalLoginCallback</code> از کنترلر <code>Account</code> صدا زده می‌شود. برای گرفتن اطلاعات لاگین کاربر مانند <code>access_token</code>  و یا  <code>id_token</code> به روش زیر عمل کنید:</blockquote>
<br/>

``` csharp
var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
if (loginInfo == null)
{
    return RedirectToAction("Login");
}
var accessToken = loginInfo.ExternalIdentity.Claims.First(c => c.Type.Equals("access_token")).Value;

```
<br/>

**<p dir="rtl">6. توجه داشته باشید به هنگام خروج کاربر ، پس از انجام عملیات خروج از سامانه خود، کاربر را به آدرس زیر هدایت کنید. بدین منظور در متد <code>LogOff</code> از کنترلر <code>Account</code> همانند زیر عمل کنید:</p>**

``` csharp
public ActionResult LogOff()
{
    AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
    return Redirect(System.Configuration.ConfigurationManager.AppSettings["BaseUrl"] +  "/logout");
}
```
<br/>

**<p dir="rtl">7. برای رفرش کردن توکن میتوانید از <code>API</code> موجود در <code>Authin.Api.Sdk</code> به روش زیر استفاده کنید:</p>**

``` csharp
var builder = RefreshTokenRequest.GetBuilder();
var request = builder
		.SetGrantType("refresh_token")
		.SetAccessToken("your_access_token")
		.SetRefreshToken("your_refresh_token")
		.SetScopes(new List<string> {"some_scope", "some_another_scope"})
		.SetClientId("your_client_id")
		.SetClientSecret("your_client_secret")
		.Build();

var newToken = await request.Execute();

```
<br/>


**<p dir="rtl">8. برای گرفتن اطلاعات کاربر (<code>userinfo</code>) میتوانید از <code>API</code> موجود در <code>Authin.Api.Sdk</code> به روش زیر استفاده کنید:</p>**


``` csharp
var builder = UserInfoRequest.GetBuilder();
var request = builder
        .SetAccessToken("your_access_token")
		.SetMethod(Method.Get)
		.Build();

var userinfo = await request.Execute();

```

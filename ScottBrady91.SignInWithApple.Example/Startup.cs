using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady91.SignInWithApple.Example
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;

            services.AddControllersWithViews();

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "cookie";
                    options.DefaultChallengeScheme = "apple";
                })
                .AddCookie("cookie")
                .AddOpenIdConnect("apple", options =>
                {
                    options.Authority = "https://appleid.apple.com"; // disco doc: https://appleid.apple.com/.well-known/openid-configuration

                    options.ClientId = "com.scottbrady91.authdemo.service"; // Service ID
                    options.CallbackPath = "/signin-apple"; // corresponding to your redirect URI

                    options.ResponseType = "code id_token"; // hybrid flow due to lack of PKCE support
                    options.SignInScheme = "cookie";
                    options.DisableTelemetry = true;

                    options.Scope.Clear(); // apple does not support the profile scope
                    options.Scope.Add("openid");
                    options.Scope.Add("email");
                    options.Scope.Add("name");

                    // custom client secret generation - secret can be re-used for up to 6 months
                    options.Events.OnAuthorizationCodeReceived = context =>
                    {
                        context.TokenEndpointRequest.ClientSecret = TokenGenerator.CreateNewToken();
                        return Task.CompletedTask;
                    };

                    options.UsePkce = false; // apple does not currently support PKCE (April 2021)
                });
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(e => e.MapDefaultControllerRoute());
        }
    }

    public static class TokenGenerator
    {
        public static string CreateNewToken()
        {
            const string iss = "62QM29578N"; // your accounts team ID found in the dev portal
            const string aud = "https://appleid.apple.com";
            const string sub = "com.scottbrady91.authdemo.service"; // same as client_id
            var now = DateTime.UtcNow;
            
            const string privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgnbfHJQO9feC7yKOenScNctvHUP+Hp3AdOKnjUC3Ee9GgCgYIKoZIzj0DAQehRANCAATMgckuqQ1MhKALhLT/CA9lZrLA+VqTW/iIJ9GKimtC2GP02hCc5Vac8WuN6YjynF3JPWKTYjg2zqex5Sdn9Wj+";
            var ecdsa = ECDsa.Create();
            ecdsa?.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);

            var handler = new JsonWebTokenHandler();
            return handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = iss,
                Audience = aud,
                Claims = new Dictionary<string, object> {{"sub", sub}},
                Expires = now.AddMinutes(5), // expiry can be a maximum of 6 months - generate one per request or re-use until expiration
                IssuedAt = now,
                NotBefore = now,
                SigningCredentials = new SigningCredentials(new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256)
            });
        }
    }
}

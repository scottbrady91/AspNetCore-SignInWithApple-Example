using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace ScottBrady91.SignInWithApple.Example
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "cookie";
                    options.DefaultChallengeScheme = "apple";
                })
                .AddCookie("cookie")
                .AddOpenIdConnect("apple", async options =>
                {
                    options.Configuration = new OpenIdConnectConfiguration
                    {
                        AuthorizationEndpoint = "https://appleid.apple.com/auth/authorize",
                        TokenEndpoint = "https://appleid.apple.com/auth/token",
                        JwksUri = "https://appleid.apple.com/auth/keys"
                    };
                    
                    options.ClientId = "com.scottbrady91.authdemo.service"; // Service ID
                    options.CallbackPath = "/signin-apple"; // corresponding to our redirect URI
                    options.ResponseType = "code";
                    options.SignInScheme = "cookie";

                    options.Scope.Clear();
                    //options.Scope.Add("openid");

                    options.DisableTelemetry = true;

                    options.Events.OnAuthorizationCodeReceived = context =>
                    {
                        context.TokenEndpointRequest.ClientSecret = TokenGenerator.CreateNewToken();
                        return Task.CompletedTask;
                    };

                    options.Events.OnTokenResponseReceived = context => Task.CompletedTask;

                    options.TokenValidationParameters.ValidIssuer = "https://appleid.apple.com";

                    var jwks = await new HttpClient().GetStringAsync("https://appleid.apple.com/auth/keys");
                    options.TokenValidationParameters.IssuerSigningKey = new JsonWebKeySet(jwks).Keys.FirstOrDefault();

                    options.ProtocolValidator.RequireNonce = false;
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseDeveloperExceptionPage();

            app.UseAuthentication();
            
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }

    public static class TokenGenerator
    {
        public static string CreateNewToken()
        {
            const string kid = "9S72H84ACK"; // from viewing the details of the key we generated using the dev portal
            const string iss = "62QM29578N"; // your accounts team ID found in the dev portal
            const string aud = "https://appleid.apple.com";
            const string sub = "com.scottbrady91.authdemo.service"; // same as client_id
            
            const string privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgnbfHJQO9feC7yKOenScNctvHUP+Hp3AdOKnjUC3Ee9GgCgYIKoZIzj0DAQehRANCAATMgckuqQ1MhKALhLT/CA9lZrLA+VqTW/iIJ9GKimtC2GP02hCc5Vac8WuN6YjynF3JPWKTYjg2zqex5Sdn9Wj+";
            var cngKey = CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.Pkcs8PrivateBlob);
            
            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateJwtSecurityToken(
                issuer: iss,
                audience: aud,
                subject: new ClaimsIdentity(new List<Claim> { new Claim("sub", sub) }),
                expires: DateTime.UtcNow.AddMinutes(5), // expiry can be a maximum of 6 months => generate one per request, or one and then re-use until expiration
                issuedAt: DateTime.UtcNow,
                notBefore: DateTime.UtcNow,
                signingCredentials: new SigningCredentials(new ECDsaSecurityKey(new ECDsaCng(cngKey)), SecurityAlgorithms.EcdsaSha256));

            // TODO: kid missing from header?

            return handler.WriteToken(token);
        }
    }
}

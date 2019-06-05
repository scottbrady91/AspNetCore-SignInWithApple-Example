using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace ScottBrady91.SignInWithApple.Example
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "cookie";
                    options.DefaultChallengeScheme = "apple";
                })
                .AddCookie("cookie")
                .AddOpenIdConnect("apple", options =>
                {
                    options.Authority = "https://appleid.apple.com";
                    options.Configuration = new OpenIdConnectConfiguration
                    {
                        AuthorizationEndpoint = "https://appleid.apple.com/auth/authorize",
                        TokenEndpoint = "https://appleid.apple.com/auth/token"
                    };

                    options.ClientId = "com.scottbrady91.authdemo.service"; // Service ID
                    options.CallbackPath = "/signin-apple"; // corresponding to our redirect URI
                    options.ResponseType = "code";

                    options.Scope.Clear();
                    options.Scope.Add("openid");

                    options.ClientSecret = "";

                    options.DisableTelemetry = true;
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}

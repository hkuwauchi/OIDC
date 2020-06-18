using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.OpenApi.Models;

namespace OIDC
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            string url = $"http://share-ubuntu:8080/auth/realms/{Configuration["Keycloak:Realm"]}/protocol/openid-connect/auth";

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "OIDC API", Version = "v1" });
                c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
                {
                    Type = SecuritySchemeType.OAuth2,
                    Flows = new OpenApiOAuthFlows
                    {
                        Implicit = new OpenApiOAuthFlow
                        {
                            AuthorizationUrl = new Uri(url, UriKind.Absolute),
                            Scopes = new Dictionary<string, string>
                            {
                                //{ "readAccess", "Access read operations" },
                                //{ "writeAccess", "Access write operations" }
                            }
                        }
                    }
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "oauth2" }
                        },
                        //new[] { "readAccess", "writeAccess" }
                        Array.Empty<string>()
                    }
                });

                c.OperationFilter<OAuth2OperationFilter>();
            });

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(o => o.LoginPath = new PathString("/login"))
                .AddOpenIdConnect("oidc", options =>
                {
                    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

                    options.Authority = $"http://share-ubuntu:8080/auth/realms/{Configuration["Keycloak:Realm"]}/protocol/openid-connect/auth";
                    options.RequireHttpsMetadata = false;

                    options.ClientId = Configuration["Keycloak:ClientId"];
                    options.ClientSecret = Configuration["Keycloak:Secret"];
                    options.ResponseType = $"{OpenIdConnectParameterNames.Code} {OpenIdConnectParameterNames.AccessToken}";

                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;
                });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseSwagger();

            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "OIDC API V1");
                c.OAuthClientId(Configuration["Keycloak:ClientId"]);
                c.OAuthClientSecret(Configuration["Keycloak:Secret"]);
                c.OAuthRealm(Configuration["Keycloak:Realm"]);
                c.OAuthAppName(Configuration["Keycloak:AppName"]);
                c.OAuthUseBasicAuthenticationWithAccessCodeGrant();
            });

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

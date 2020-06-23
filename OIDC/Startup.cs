using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace OIDC
{
    public class Startup
    {
        public Startup(IConfiguration configuration, IWebHostEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Environment { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            string url = $"http://share-ubuntu:8080/auth/realms/{Configuration["Keycloak:Realm"]}/protocol/openid-connect/auth";

            var cert = new X509Certificate2(Path.Combine(Environment.ContentRootPath, "keycloak.crt"), "");
            X509SecurityKey key = new X509SecurityKey(cert);
            SigningCredentials credentials = new SigningCredentials(key, "RS256");


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


                //c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                //{
                //    Name = "Authorization",
                //    Type = SecuritySchemeType.ApiKey,
                //    Scheme = "Bearer",
                //    BearerFormat = "JWT",
                //    In = ParameterLocation.Header,
                //    Description = "JWT Authorization header using the Bearer scheme."
                //});

                //c.AddSecurityRequirement(new OpenApiSecurityRequirement
                //{
                //    {
                //          new OpenApiSecurityScheme
                //            {
                //                Reference = new OpenApiReference
                //                {
                //                    Type = ReferenceType.SecurityScheme,
                //                    Id = "Bearer"
                //                }
                //            },
                //            Array.Empty<string>()

                //    }
                //});

                c.OperationFilter<OAuth2OperationFilter>();
            });

            services.AddAuthentication(option =>
            {
                option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

            }).AddJwtBearer(options =>
            {
                options.Authority = $"http://share-ubuntu:8080/auth/realms/{Configuration["Keycloak:Realm"]}";
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = Configuration["Keycloak:Issuer"],
                    //ValidAudience = Configuration["Keycloak:Issuer"],
                    ValidAudience = "account",
                    IssuerSigningKey = key
                };
            });

            //services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            //    .AddCookie(o => o.LoginPath = new PathString("/login"))
            //    .AddOpenIdConnect("oidc", options =>
            //    {
            //        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

            //        options.Authority = $"http://share-ubuntu:8080/auth/realms/{Configuration["Keycloak:Realm"]}/protocol/openid-connect/auth";
            //        options.RequireHttpsMetadata = false;

            //        options.ClientId = Configuration["Keycloak:ClientId"];
            //        options.ClientSecret = Configuration["Keycloak:Secret"];
            //        options.ResponseType = $"{OpenIdConnectParameterNames.Code} {OpenIdConnectParameterNames.AccessToken}";

            //        options.SaveTokens = true;
            //        options.GetClaimsFromUserInfoEndpoint = true;
            //    });

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

            app.UseCors(option => option
               .AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader());

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}

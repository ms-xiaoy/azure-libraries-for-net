// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

//using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Identity.Client;
using Microsoft.Rest;
//using Microsoft.Rest.Azure.Authentication;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IdentityModel;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Azure.Management.ResourceManager.Fluent.Authentication
{
    /// <summary>
    /// Credentials used for authenticating a fluent management client to Azure.
    /// </summary>
    public class AzureCredentials : ServiceClientCredentials
    {
        private ServicePrincipalLoginInformation servicePrincipalLoginInformation;
        private MSITokenProviderFactory msiTokenProviderFactory;
        private IDictionary<Uri, ServiceClientCredentials> credentialsCache;
        private UserLoginInformation userLoginInformation;
        private DeviceCredentialInformation deviceCredentialInformation;

        public string DefaultSubscriptionId { get; private set; }

        public string TenantId { get; private set; }

        public string ClientId
        {
            get
            {
                if (userLoginInformation != null && userLoginInformation.ClientId != null)
                {
                    return userLoginInformation.ClientId;
                }
                if (deviceCredentialInformation != null && deviceCredentialInformation.ClientId != null)
                {
                    return deviceCredentialInformation.ClientId;
                }

                return servicePrincipalLoginInformation?.ClientId;
            }
        }

        public AzureEnvironment Environment { get; private set; }

        public AzureCredentials(UserLoginInformation userLoginInformation, string tenantId, AzureEnvironment environment)
            : this(tenantId, environment)
        {
            this.userLoginInformation = userLoginInformation;
        }

        public AzureCredentials(DeviceCredentialInformation deviceCredentialInformation, string tenantId, AzureEnvironment environment)
            : this(tenantId, environment)
        {
            this.deviceCredentialInformation = deviceCredentialInformation;

        }

        public AzureCredentials(ServicePrincipalLoginInformation servicePrincipalLoginInformation, string tenantId, AzureEnvironment environment)
            : this(tenantId, environment)
        {
            this.servicePrincipalLoginInformation = servicePrincipalLoginInformation;
        }

        public AzureCredentials(MSILoginInformation msiLoginInformation, AzureEnvironment environment, string tenantId = null)
            : this(tenantId: tenantId, environment: environment)
        {
            this.msiTokenProviderFactory = new MSITokenProviderFactory(msiLoginInformation);
        }

        public AzureCredentials(
            ServiceClientCredentials armCredentials,
            ServiceClientCredentials graphCredentials,
            string tenantId, AzureEnvironment environment)
            : this(tenantId, environment)
        {
            if (armCredentials != null)
            {
                credentialsCache[new Uri(Environment.ManagementEndpoint)] = armCredentials;
            }
            if (graphCredentials != null)
            {
                credentialsCache[new Uri(Environment.GraphEndpoint)] = graphCredentials;
            }
        }

        private AzureCredentials(string tenantId, AzureEnvironment environment)
        {
            TenantId = tenantId;
            Environment = environment;
            credentialsCache = new ConcurrentDictionary<Uri, ServiceClientCredentials>();
        }

        public AzureCredentials WithDefaultSubscription(string subscriptionId)
        {
            DefaultSubscriptionId = subscriptionId;
            return this;
        }

        public async override Task ProcessHttpRequestAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var authenticationEndpoint = new Uri(Environment.AuthenticationEndpoint);
            var tokenAudience = new Uri(Environment.ManagementEndpoint);
            var validateAuthority = true;

            string url = request.RequestUri.ToString();
            if (url.StartsWith(Environment.GraphEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                tokenAudience = new Uri(Environment.GraphEndpoint);
            }

            string host = request.RequestUri.Host;
            if (host.EndsWith(Environment.KeyVaultSuffix, StringComparison.OrdinalIgnoreCase))
            {
                var resource = new Uri(Regex.Replace(Environment.KeyVaultSuffix, "^.", "https://"));
                if (credentialsCache.ContainsKey(new Uri(Regex.Replace(Environment.KeyVaultSuffix, "^.", "https://"))))
                {
                    tokenAudience = resource;
                }
                else
                {
                    using (var r = new HttpRequestMessage(request.Method, url))
                    {
                        var response = await new HttpClient().SendAsync(r).ConfigureAwait(false);

                        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && response.Headers.WwwAuthenticate != null)
                        {
                            var header = response.Headers.WwwAuthenticate.ElementAt(0).ToString();
                            var regex = new Regex("authorization=\"([^\"]+)\"");
                            var match = regex.Match(header);
                            authenticationEndpoint = new Uri(match.Groups[1].Value);
                            regex = new Regex("resource=\"([^\"]+)\"");
                            match = regex.Match(header);
                            tokenAudience = new Uri(match.Groups[1].Value);
                        }
                    }
                }
            }

            var scope = new Uri(tokenAudience, ".default").OriginalString;
            var authority = new Uri(authenticationEndpoint, TenantId);
            var appBuilder = ConfidentialClientApplicationBuilder.Create(ClientId).WithAuthority(authority, validateAuthority);

            if (!credentialsCache.ContainsKey(tokenAudience))
            {
                if (servicePrincipalLoginInformation != null)
                {
                    if (servicePrincipalLoginInformation.ClientId == null)
                    {
                        throw new RestException($"Cannot communicate with server. ServicePrincipalLoginInformation should contain a valid ClientId information.");
                    }
                    if (servicePrincipalLoginInformation.ClientSecret != null)
                    {
                        appBuilder.WithClientSecret(servicePrincipalLoginInformation.ClientSecret);
                    }
                    else if (servicePrincipalLoginInformation.X509Certificate != null)
                    {
                        appBuilder.WithCertificate(servicePrincipalLoginInformation.X509Certificate);
                    }
                    else if (servicePrincipalLoginInformation.Certificate != null)
                    {
                        appBuilder.WithCertificate(new X509Certificate2(servicePrincipalLoginInformation.Certificate, servicePrincipalLoginInformation.CertificatePassword));
                    }
                    else
                    {
                        throw new RestException($"Cannot communicate with server. ServicePrincipalLoginInformation should contain either a valid ClientSecret or Certificate information.");
                    }

                    var app = appBuilder.Build();
                    var authResult = await app.AcquireTokenForClient(new[] { scope })
                        .ExecuteAsync()
                        .ConfigureAwait(false);

                    credentialsCache[tokenAudience] = new TokenCredentials(authResult.AccessToken);
                }
                else if (userLoginInformation != null)
                {
                    throw new NotImplementedException();
                }
                else if (deviceCredentialInformation != null)
                {
                    //https://learn.microsoft.com/en-us/entra/msal/dotnet/acquiring-tokens/desktop-mobile/device-code-flow
                    throw new NotImplementedException();
                }
                else if (msiTokenProviderFactory != null)
                {
                    credentialsCache[tokenAudience] = new TokenCredentials(this.msiTokenProviderFactory.Create(tokenAudience.OriginalString));
                }
                else
                {
                    throw new RestException($"Cannot communicate with server. No authentication token available for '{tokenAudience}'.");
                }
            }

            await credentialsCache[tokenAudience].ProcessHttpRequestAsync(request, cancellationToken);
        }
    }
}
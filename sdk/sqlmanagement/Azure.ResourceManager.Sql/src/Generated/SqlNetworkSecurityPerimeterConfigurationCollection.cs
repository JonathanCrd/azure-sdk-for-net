// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Autorest.CSharp.Core;
using Azure.Core;
using Azure.Core.Pipeline;

namespace Azure.ResourceManager.Sql
{
    /// <summary>
    /// A class representing a collection of <see cref="SqlNetworkSecurityPerimeterConfigurationResource"/> and their operations.
    /// Each <see cref="SqlNetworkSecurityPerimeterConfigurationResource"/> in the collection will belong to the same instance of <see cref="SqlServerResource"/>.
    /// To get a <see cref="SqlNetworkSecurityPerimeterConfigurationCollection"/> instance call the GetSqlNetworkSecurityPerimeterConfigurations method from an instance of <see cref="SqlServerResource"/>.
    /// </summary>
    public partial class SqlNetworkSecurityPerimeterConfigurationCollection : ArmCollection, IEnumerable<SqlNetworkSecurityPerimeterConfigurationResource>, IAsyncEnumerable<SqlNetworkSecurityPerimeterConfigurationResource>
    {
        private readonly ClientDiagnostics _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics;
        private readonly NetworkSecurityPerimeterConfigurationsRestOperations _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient;

        /// <summary> Initializes a new instance of the <see cref="SqlNetworkSecurityPerimeterConfigurationCollection"/> class for mocking. </summary>
        protected SqlNetworkSecurityPerimeterConfigurationCollection()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="SqlNetworkSecurityPerimeterConfigurationCollection"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the parent resource that is the target of operations. </param>
        internal SqlNetworkSecurityPerimeterConfigurationCollection(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.Sql", SqlNetworkSecurityPerimeterConfigurationResource.ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(SqlNetworkSecurityPerimeterConfigurationResource.ResourceType, out string sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsApiVersion);
            _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient = new NetworkSecurityPerimeterConfigurationsRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsApiVersion);
#if DEBUG
			ValidateResourceId(Id);
#endif
        }

        internal static void ValidateResourceId(ResourceIdentifier id)
        {
            if (id.ResourceType != SqlServerResource.ResourceType)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Invalid resource type {0} expected {1}", id.ResourceType, SqlServerResource.ResourceType), nameof(id));
        }

        /// <summary>
        /// Gets a network security perimeter configuration.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations/{nspConfigName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="nspConfigName"> The <see cref="string"/> to use. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="nspConfigName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="nspConfigName"/> is null. </exception>
        public virtual async Task<Response<SqlNetworkSecurityPerimeterConfigurationResource>> GetAsync(string nspConfigName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(nspConfigName, nameof(nspConfigName));

            using var scope = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics.CreateScope("SqlNetworkSecurityPerimeterConfigurationCollection.Get");
            scope.Start();
            try
            {
                var response = await _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Name, nspConfigName, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new SqlNetworkSecurityPerimeterConfigurationResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets a network security perimeter configuration.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations/{nspConfigName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="nspConfigName"> The <see cref="string"/> to use. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="nspConfigName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="nspConfigName"/> is null. </exception>
        public virtual Response<SqlNetworkSecurityPerimeterConfigurationResource> Get(string nspConfigName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(nspConfigName, nameof(nspConfigName));

            using var scope = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics.CreateScope("SqlNetworkSecurityPerimeterConfigurationCollection.Get");
            scope.Start();
            try
            {
                var response = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Name, nspConfigName, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new SqlNetworkSecurityPerimeterConfigurationResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets a list of NSP configurations for a server.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_ListByServer</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> An async collection of <see cref="SqlNetworkSecurityPerimeterConfigurationResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual AsyncPageable<SqlNetworkSecurityPerimeterConfigurationResource> GetAllAsync(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.CreateListByServerRequest(Id.SubscriptionId, Id.ResourceGroupName, Id.Name);
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.CreateListByServerNextPageRequest(nextLink, Id.SubscriptionId, Id.ResourceGroupName, Id.Name);
            return GeneratorPageableHelpers.CreateAsyncPageable(FirstPageRequest, NextPageRequest, e => new SqlNetworkSecurityPerimeterConfigurationResource(Client, SqlNetworkSecurityPerimeterConfigurationData.DeserializeSqlNetworkSecurityPerimeterConfigurationData(e)), _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics, Pipeline, "SqlNetworkSecurityPerimeterConfigurationCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// Gets a list of NSP configurations for a server.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_ListByServer</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> A collection of <see cref="SqlNetworkSecurityPerimeterConfigurationResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual Pageable<SqlNetworkSecurityPerimeterConfigurationResource> GetAll(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.CreateListByServerRequest(Id.SubscriptionId, Id.ResourceGroupName, Id.Name);
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.CreateListByServerNextPageRequest(nextLink, Id.SubscriptionId, Id.ResourceGroupName, Id.Name);
            return GeneratorPageableHelpers.CreatePageable(FirstPageRequest, NextPageRequest, e => new SqlNetworkSecurityPerimeterConfigurationResource(Client, SqlNetworkSecurityPerimeterConfigurationData.DeserializeSqlNetworkSecurityPerimeterConfigurationData(e)), _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics, Pipeline, "SqlNetworkSecurityPerimeterConfigurationCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// Checks to see if the resource exists in azure.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations/{nspConfigName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="nspConfigName"> The <see cref="string"/> to use. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="nspConfigName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="nspConfigName"/> is null. </exception>
        public virtual async Task<Response<bool>> ExistsAsync(string nspConfigName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(nspConfigName, nameof(nspConfigName));

            using var scope = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics.CreateScope("SqlNetworkSecurityPerimeterConfigurationCollection.Exists");
            scope.Start();
            try
            {
                var response = await _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Name, nspConfigName, cancellationToken: cancellationToken).ConfigureAwait(false);
                return Response.FromValue(response.Value != null, response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Checks to see if the resource exists in azure.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations/{nspConfigName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="nspConfigName"> The <see cref="string"/> to use. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="nspConfigName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="nspConfigName"/> is null. </exception>
        public virtual Response<bool> Exists(string nspConfigName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(nspConfigName, nameof(nspConfigName));

            using var scope = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics.CreateScope("SqlNetworkSecurityPerimeterConfigurationCollection.Exists");
            scope.Start();
            try
            {
                var response = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Name, nspConfigName, cancellationToken: cancellationToken);
                return Response.FromValue(response.Value != null, response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Tries to get details for this resource from the service.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations/{nspConfigName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="nspConfigName"> The <see cref="string"/> to use. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="nspConfigName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="nspConfigName"/> is null. </exception>
        public virtual async Task<NullableResponse<SqlNetworkSecurityPerimeterConfigurationResource>> GetIfExistsAsync(string nspConfigName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(nspConfigName, nameof(nspConfigName));

            using var scope = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics.CreateScope("SqlNetworkSecurityPerimeterConfigurationCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = await _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Name, nspConfigName, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    return new NoValueResponse<SqlNetworkSecurityPerimeterConfigurationResource>(response.GetRawResponse());
                return Response.FromValue(new SqlNetworkSecurityPerimeterConfigurationResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Tries to get details for this resource from the service.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/networkSecurityPerimeterConfigurations/{nspConfigName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>NetworkSecurityPerimeterConfigurations_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlNetworkSecurityPerimeterConfigurationResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="nspConfigName"> The <see cref="string"/> to use. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="nspConfigName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="nspConfigName"/> is null. </exception>
        public virtual NullableResponse<SqlNetworkSecurityPerimeterConfigurationResource> GetIfExists(string nspConfigName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(nspConfigName, nameof(nspConfigName));

            using var scope = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsClientDiagnostics.CreateScope("SqlNetworkSecurityPerimeterConfigurationCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = _sqlNetworkSecurityPerimeterConfigurationNetworkSecurityPerimeterConfigurationsRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Name, nspConfigName, cancellationToken: cancellationToken);
                if (response.Value == null)
                    return new NoValueResponse<SqlNetworkSecurityPerimeterConfigurationResource>(response.GetRawResponse());
                return Response.FromValue(new SqlNetworkSecurityPerimeterConfigurationResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        IEnumerator<SqlNetworkSecurityPerimeterConfigurationResource> IEnumerable<SqlNetworkSecurityPerimeterConfigurationResource>.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IAsyncEnumerator<SqlNetworkSecurityPerimeterConfigurationResource> IAsyncEnumerable<SqlNetworkSecurityPerimeterConfigurationResource>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return GetAllAsync(cancellationToken: cancellationToken).GetAsyncEnumerator(cancellationToken);
        }
    }
}

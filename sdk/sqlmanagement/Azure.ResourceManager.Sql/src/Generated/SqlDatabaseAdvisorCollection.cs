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
    /// A class representing a collection of <see cref="SqlDatabaseAdvisorResource"/> and their operations.
    /// Each <see cref="SqlDatabaseAdvisorResource"/> in the collection will belong to the same instance of <see cref="SqlDatabaseResource"/>.
    /// To get a <see cref="SqlDatabaseAdvisorCollection"/> instance call the GetSqlDatabaseAdvisors method from an instance of <see cref="SqlDatabaseResource"/>.
    /// </summary>
    public partial class SqlDatabaseAdvisorCollection : ArmCollection, IEnumerable<SqlDatabaseAdvisorResource>, IAsyncEnumerable<SqlDatabaseAdvisorResource>
    {
        private readonly ClientDiagnostics _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics;
        private readonly DatabaseAdvisorsRestOperations _sqlDatabaseAdvisorDatabaseAdvisorsRestClient;

        /// <summary> Initializes a new instance of the <see cref="SqlDatabaseAdvisorCollection"/> class for mocking. </summary>
        protected SqlDatabaseAdvisorCollection()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="SqlDatabaseAdvisorCollection"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the parent resource that is the target of operations. </param>
        internal SqlDatabaseAdvisorCollection(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.Sql", SqlDatabaseAdvisorResource.ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(SqlDatabaseAdvisorResource.ResourceType, out string sqlDatabaseAdvisorDatabaseAdvisorsApiVersion);
            _sqlDatabaseAdvisorDatabaseAdvisorsRestClient = new DatabaseAdvisorsRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, sqlDatabaseAdvisorDatabaseAdvisorsApiVersion);
#if DEBUG
			ValidateResourceId(Id);
#endif
        }

        internal static void ValidateResourceId(ResourceIdentifier id)
        {
            if (id.ResourceType != SqlDatabaseResource.ResourceType)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Invalid resource type {0} expected {1}", id.ResourceType, SqlDatabaseResource.ResourceType), nameof(id));
        }

        /// <summary>
        /// Gets a database advisor.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors/{advisorName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="advisorName"> The name of the Database Advisor. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="advisorName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="advisorName"/> is null. </exception>
        public virtual async Task<Response<SqlDatabaseAdvisorResource>> GetAsync(string advisorName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(advisorName, nameof(advisorName));

            using var scope = _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics.CreateScope("SqlDatabaseAdvisorCollection.Get");
            scope.Start();
            try
            {
                var response = await _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, advisorName, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new SqlDatabaseAdvisorResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets a database advisor.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors/{advisorName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="advisorName"> The name of the Database Advisor. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="advisorName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="advisorName"/> is null. </exception>
        public virtual Response<SqlDatabaseAdvisorResource> Get(string advisorName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(advisorName, nameof(advisorName));

            using var scope = _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics.CreateScope("SqlDatabaseAdvisorCollection.Get");
            scope.Start();
            try
            {
                var response = _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, advisorName, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new SqlDatabaseAdvisorResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets a list of database advisors.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_ListByDatabase</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="expand"> The child resources to include in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> An async collection of <see cref="SqlDatabaseAdvisorResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual AsyncPageable<SqlDatabaseAdvisorResource> GetAllAsync(string expand = null, CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.CreateListByDatabaseRequest(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, expand);
            return GeneratorPageableHelpers.CreateAsyncPageable(FirstPageRequest, null, e => new SqlDatabaseAdvisorResource(Client, SqlAdvisorData.DeserializeSqlAdvisorData(e)), _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics, Pipeline, "SqlDatabaseAdvisorCollection.GetAll", "", null, cancellationToken);
        }

        /// <summary>
        /// Gets a list of database advisors.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_ListByDatabase</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="expand"> The child resources to include in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> A collection of <see cref="SqlDatabaseAdvisorResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual Pageable<SqlDatabaseAdvisorResource> GetAll(string expand = null, CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.CreateListByDatabaseRequest(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, expand);
            return GeneratorPageableHelpers.CreatePageable(FirstPageRequest, null, e => new SqlDatabaseAdvisorResource(Client, SqlAdvisorData.DeserializeSqlAdvisorData(e)), _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics, Pipeline, "SqlDatabaseAdvisorCollection.GetAll", "", null, cancellationToken);
        }

        /// <summary>
        /// Checks to see if the resource exists in azure.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors/{advisorName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="advisorName"> The name of the Database Advisor. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="advisorName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="advisorName"/> is null. </exception>
        public virtual async Task<Response<bool>> ExistsAsync(string advisorName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(advisorName, nameof(advisorName));

            using var scope = _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics.CreateScope("SqlDatabaseAdvisorCollection.Exists");
            scope.Start();
            try
            {
                var response = await _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, advisorName, cancellationToken: cancellationToken).ConfigureAwait(false);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors/{advisorName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="advisorName"> The name of the Database Advisor. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="advisorName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="advisorName"/> is null. </exception>
        public virtual Response<bool> Exists(string advisorName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(advisorName, nameof(advisorName));

            using var scope = _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics.CreateScope("SqlDatabaseAdvisorCollection.Exists");
            scope.Start();
            try
            {
                var response = _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, advisorName, cancellationToken: cancellationToken);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors/{advisorName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="advisorName"> The name of the Database Advisor. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="advisorName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="advisorName"/> is null. </exception>
        public virtual async Task<NullableResponse<SqlDatabaseAdvisorResource>> GetIfExistsAsync(string advisorName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(advisorName, nameof(advisorName));

            using var scope = _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics.CreateScope("SqlDatabaseAdvisorCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = await _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, advisorName, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    return new NoValueResponse<SqlDatabaseAdvisorResource>(response.GetRawResponse());
                return Response.FromValue(new SqlDatabaseAdvisorResource(Client, response.Value), response.GetRawResponse());
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/advisors/{advisorName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseAdvisors_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="SqlDatabaseAdvisorResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="advisorName"> The name of the Database Advisor. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="advisorName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="advisorName"/> is null. </exception>
        public virtual NullableResponse<SqlDatabaseAdvisorResource> GetIfExists(string advisorName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(advisorName, nameof(advisorName));

            using var scope = _sqlDatabaseAdvisorDatabaseAdvisorsClientDiagnostics.CreateScope("SqlDatabaseAdvisorCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = _sqlDatabaseAdvisorDatabaseAdvisorsRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, advisorName, cancellationToken: cancellationToken);
                if (response.Value == null)
                    return new NoValueResponse<SqlDatabaseAdvisorResource>(response.GetRawResponse());
                return Response.FromValue(new SqlDatabaseAdvisorResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        IEnumerator<SqlDatabaseAdvisorResource> IEnumerable<SqlDatabaseAdvisorResource>.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IAsyncEnumerator<SqlDatabaseAdvisorResource> IAsyncEnumerable<SqlDatabaseAdvisorResource>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return GetAllAsync(cancellationToken: cancellationToken).GetAsyncEnumerator(cancellationToken);
        }
    }
}

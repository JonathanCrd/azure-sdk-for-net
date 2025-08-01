// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager.Sql.Models;

namespace Azure.ResourceManager.Sql
{
    /// <summary>
    /// A class representing a collection of <see cref="DataMaskingPolicyResource"/> and their operations.
    /// Each <see cref="DataMaskingPolicyResource"/> in the collection will belong to the same instance of <see cref="SqlDatabaseResource"/>.
    /// To get a <see cref="DataMaskingPolicyCollection"/> instance call the GetDataMaskingPolicies method from an instance of <see cref="SqlDatabaseResource"/>.
    /// </summary>
    public partial class DataMaskingPolicyCollection : ArmCollection
    {
        private readonly ClientDiagnostics _dataMaskingPolicyClientDiagnostics;
        private readonly DataMaskingPoliciesRestOperations _dataMaskingPolicyRestClient;

        /// <summary> Initializes a new instance of the <see cref="DataMaskingPolicyCollection"/> class for mocking. </summary>
        protected DataMaskingPolicyCollection()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="DataMaskingPolicyCollection"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the parent resource that is the target of operations. </param>
        internal DataMaskingPolicyCollection(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _dataMaskingPolicyClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.Sql", DataMaskingPolicyResource.ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(DataMaskingPolicyResource.ResourceType, out string dataMaskingPolicyApiVersion);
            _dataMaskingPolicyRestClient = new DataMaskingPoliciesRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, dataMaskingPolicyApiVersion);
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
        /// Creates or updates a database data masking policy.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_CreateOrUpdate</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="data"> Parameters for creating or updating a data masking policy. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="data"/> is null. </exception>
        public virtual async Task<ArmOperation<DataMaskingPolicyResource>> CreateOrUpdateAsync(WaitUntil waitUntil, DataMaskingPolicyName dataMaskingPolicyName, DataMaskingPolicyData data, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(data, nameof(data));

            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = await _dataMaskingPolicyRestClient.CreateOrUpdateAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, data, cancellationToken).ConfigureAwait(false);
                var uri = _dataMaskingPolicyRestClient.CreateCreateOrUpdateRequestUri(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, data);
                var rehydrationToken = NextLinkOperationImplementation.GetRehydrationToken(RequestMethod.Put, uri.ToUri(), uri.ToString(), "None", null, OperationFinalStateVia.OriginalUri.ToString());
                var operation = new SqlArmOperation<DataMaskingPolicyResource>(Response.FromValue(new DataMaskingPolicyResource(Client, response), response.GetRawResponse()), rehydrationToken);
                if (waitUntil == WaitUntil.Completed)
                    await operation.WaitForCompletionAsync(cancellationToken).ConfigureAwait(false);
                return operation;
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Creates or updates a database data masking policy.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_CreateOrUpdate</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="data"> Parameters for creating or updating a data masking policy. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="data"/> is null. </exception>
        public virtual ArmOperation<DataMaskingPolicyResource> CreateOrUpdate(WaitUntil waitUntil, DataMaskingPolicyName dataMaskingPolicyName, DataMaskingPolicyData data, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(data, nameof(data));

            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = _dataMaskingPolicyRestClient.CreateOrUpdate(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, data, cancellationToken);
                var uri = _dataMaskingPolicyRestClient.CreateCreateOrUpdateRequestUri(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, data);
                var rehydrationToken = NextLinkOperationImplementation.GetRehydrationToken(RequestMethod.Put, uri.ToUri(), uri.ToString(), "None", null, OperationFinalStateVia.OriginalUri.ToString());
                var operation = new SqlArmOperation<DataMaskingPolicyResource>(Response.FromValue(new DataMaskingPolicyResource(Client, response), response.GetRawResponse()), rehydrationToken);
                if (waitUntil == WaitUntil.Completed)
                    operation.WaitForCompletion(cancellationToken);
                return operation;
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets the database data masking policy.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual async Task<Response<DataMaskingPolicyResource>> GetAsync(DataMaskingPolicyName dataMaskingPolicyName, CancellationToken cancellationToken = default)
        {
            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.Get");
            scope.Start();
            try
            {
                var response = await _dataMaskingPolicyRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new DataMaskingPolicyResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets the database data masking policy.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual Response<DataMaskingPolicyResource> Get(DataMaskingPolicyName dataMaskingPolicyName, CancellationToken cancellationToken = default)
        {
            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.Get");
            scope.Start();
            try
            {
                var response = _dataMaskingPolicyRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new DataMaskingPolicyResource(Client, response.Value), response.GetRawResponse());
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual async Task<Response<bool>> ExistsAsync(DataMaskingPolicyName dataMaskingPolicyName, CancellationToken cancellationToken = default)
        {
            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.Exists");
            scope.Start();
            try
            {
                var response = await _dataMaskingPolicyRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, cancellationToken: cancellationToken).ConfigureAwait(false);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual Response<bool> Exists(DataMaskingPolicyName dataMaskingPolicyName, CancellationToken cancellationToken = default)
        {
            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.Exists");
            scope.Start();
            try
            {
                var response = _dataMaskingPolicyRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, cancellationToken: cancellationToken);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual async Task<NullableResponse<DataMaskingPolicyResource>> GetIfExistsAsync(DataMaskingPolicyName dataMaskingPolicyName, CancellationToken cancellationToken = default)
        {
            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = await _dataMaskingPolicyRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    return new NoValueResponse<DataMaskingPolicyResource>(response.GetRawResponse());
                return Response.FromValue(new DataMaskingPolicyResource(Client, response.Value), response.GetRawResponse());
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/{dataMaskingPolicyName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DataMaskingPolicies_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DataMaskingPolicyResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="dataMaskingPolicyName"> The name of the database for which the data masking policy applies. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual NullableResponse<DataMaskingPolicyResource> GetIfExists(DataMaskingPolicyName dataMaskingPolicyName, CancellationToken cancellationToken = default)
        {
            using var scope = _dataMaskingPolicyClientDiagnostics.CreateScope("DataMaskingPolicyCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = _dataMaskingPolicyRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, Id.Parent.Name, Id.Name, dataMaskingPolicyName, cancellationToken: cancellationToken);
                if (response.Value == null)
                    return new NoValueResponse<DataMaskingPolicyResource>(response.GetRawResponse());
                return Response.FromValue(new DataMaskingPolicyResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }
    }
}

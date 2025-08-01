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
using Azure.ResourceManager.Resources;

namespace Azure.ResourceManager.DataMigration
{
    /// <summary>
    /// A class representing a collection of <see cref="DatabaseMigrationSqlMIResource"/> and their operations.
    /// Each <see cref="DatabaseMigrationSqlMIResource"/> in the collection will belong to the same instance of <see cref="ResourceGroupResource"/>.
    /// To get a <see cref="DatabaseMigrationSqlMICollection"/> instance call the GetDatabaseMigrationSqlMIs method from an instance of <see cref="ResourceGroupResource"/>.
    /// </summary>
    public partial class DatabaseMigrationSqlMICollection : ArmCollection
    {
        private readonly ClientDiagnostics _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics;
        private readonly DatabaseMigrationsSqlMiRestOperations _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient;

        /// <summary> Initializes a new instance of the <see cref="DatabaseMigrationSqlMICollection"/> class for mocking. </summary>
        protected DatabaseMigrationSqlMICollection()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="DatabaseMigrationSqlMICollection"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the parent resource that is the target of operations. </param>
        internal DatabaseMigrationSqlMICollection(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.DataMigration", DatabaseMigrationSqlMIResource.ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(DatabaseMigrationSqlMIResource.ResourceType, out string databaseMigrationSqlMIDatabaseMigrationsSqlMIApiVersion);
            _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient = new DatabaseMigrationsSqlMiRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, databaseMigrationSqlMIDatabaseMigrationsSqlMIApiVersion);
#if DEBUG
			ValidateResourceId(Id);
#endif
        }

        internal static void ValidateResourceId(ResourceIdentifier id)
        {
            if (id.ResourceType != ResourceGroupResource.ResourceType)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Invalid resource type {0} expected {1}", id.ResourceType, ResourceGroupResource.ResourceType), nameof(id));
        }

        /// <summary>
        /// Create a new database migration to a given SQL Managed Instance.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_CreateOrUpdate</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="data"> Details of SqlMigrationService resource. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/>, <paramref name="targetDBName"/> or <paramref name="data"/> is null. </exception>
        public virtual async Task<ArmOperation<DatabaseMigrationSqlMIResource>> CreateOrUpdateAsync(WaitUntil waitUntil, string managedInstanceName, string targetDBName, DatabaseMigrationSqlMIData data, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));
            Argument.AssertNotNull(data, nameof(data));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = await _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.CreateOrUpdateAsync(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, data, cancellationToken).ConfigureAwait(false);
                var operation = new DataMigrationArmOperation<DatabaseMigrationSqlMIResource>(new DatabaseMigrationSqlMIOperationSource(Client), _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics, Pipeline, _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.CreateCreateOrUpdateRequest(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, data).Request, response, OperationFinalStateVia.Location);
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
        /// Create a new database migration to a given SQL Managed Instance.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_CreateOrUpdate</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="data"> Details of SqlMigrationService resource. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/>, <paramref name="targetDBName"/> or <paramref name="data"/> is null. </exception>
        public virtual ArmOperation<DatabaseMigrationSqlMIResource> CreateOrUpdate(WaitUntil waitUntil, string managedInstanceName, string targetDBName, DatabaseMigrationSqlMIData data, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));
            Argument.AssertNotNull(data, nameof(data));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.CreateOrUpdate(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, data, cancellationToken);
                var operation = new DataMigrationArmOperation<DatabaseMigrationSqlMIResource>(new DatabaseMigrationSqlMIOperationSource(Client), _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics, Pipeline, _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.CreateCreateOrUpdateRequest(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, data).Request, response, OperationFinalStateVia.Location);
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
        /// Retrieve the specified database migration for a given SQL Managed Instance.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="migrationOperationId"> Optional migration operation ID. If this is provided, then details of migration operation for that ID are retrieved. If not provided (default), then details related to most recent or current operation are retrieved. </param>
        /// <param name="expand"> Complete migration details be included in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is null. </exception>
        public virtual async Task<Response<DatabaseMigrationSqlMIResource>> GetAsync(string managedInstanceName, string targetDBName, Guid? migrationOperationId = null, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.Get");
            scope.Start();
            try
            {
                var response = await _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, migrationOperationId, expand, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new DatabaseMigrationSqlMIResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Retrieve the specified database migration for a given SQL Managed Instance.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="migrationOperationId"> Optional migration operation ID. If this is provided, then details of migration operation for that ID are retrieved. If not provided (default), then details related to most recent or current operation are retrieved. </param>
        /// <param name="expand"> Complete migration details be included in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is null. </exception>
        public virtual Response<DatabaseMigrationSqlMIResource> Get(string managedInstanceName, string targetDBName, Guid? migrationOperationId = null, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.Get");
            scope.Start();
            try
            {
                var response = _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, migrationOperationId, expand, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new DatabaseMigrationSqlMIResource(Client, response.Value), response.GetRawResponse());
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="migrationOperationId"> Optional migration operation ID. If this is provided, then details of migration operation for that ID are retrieved. If not provided (default), then details related to most recent or current operation are retrieved. </param>
        /// <param name="expand"> Complete migration details be included in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is null. </exception>
        public virtual async Task<Response<bool>> ExistsAsync(string managedInstanceName, string targetDBName, Guid? migrationOperationId = null, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.Exists");
            scope.Start();
            try
            {
                var response = await _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, migrationOperationId, expand, cancellationToken: cancellationToken).ConfigureAwait(false);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="migrationOperationId"> Optional migration operation ID. If this is provided, then details of migration operation for that ID are retrieved. If not provided (default), then details related to most recent or current operation are retrieved. </param>
        /// <param name="expand"> Complete migration details be included in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is null. </exception>
        public virtual Response<bool> Exists(string managedInstanceName, string targetDBName, Guid? migrationOperationId = null, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.Exists");
            scope.Start();
            try
            {
                var response = _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, migrationOperationId, expand, cancellationToken: cancellationToken);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="migrationOperationId"> Optional migration operation ID. If this is provided, then details of migration operation for that ID are retrieved. If not provided (default), then details related to most recent or current operation are retrieved. </param>
        /// <param name="expand"> Complete migration details be included in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is null. </exception>
        public virtual async Task<NullableResponse<DatabaseMigrationSqlMIResource>> GetIfExistsAsync(string managedInstanceName, string targetDBName, Guid? migrationOperationId = null, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.GetIfExists");
            scope.Start();
            try
            {
                var response = await _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, migrationOperationId, expand, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    return new NoValueResponse<DatabaseMigrationSqlMIResource>(response.GetRawResponse());
                return Response.FromValue(new DatabaseMigrationSqlMIResource(Client, response.Value), response.GetRawResponse());
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/providers/Microsoft.DataMigration/databaseMigrations/{targetDbName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>DatabaseMigrationsSqlMi_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-03-15-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="DatabaseMigrationSqlMIResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="managedInstanceName"> The <see cref="string"/> to use. </param>
        /// <param name="targetDBName"> The name of the target database. </param>
        /// <param name="migrationOperationId"> Optional migration operation ID. If this is provided, then details of migration operation for that ID are retrieved. If not provided (default), then details related to most recent or current operation are retrieved. </param>
        /// <param name="expand"> Complete migration details be included in the response. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="managedInstanceName"/> or <paramref name="targetDBName"/> is null. </exception>
        public virtual NullableResponse<DatabaseMigrationSqlMIResource> GetIfExists(string managedInstanceName, string targetDBName, Guid? migrationOperationId = null, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(managedInstanceName, nameof(managedInstanceName));
            Argument.AssertNotNullOrEmpty(targetDBName, nameof(targetDBName));

            using var scope = _databaseMigrationSqlMIDatabaseMigrationsSqlMIClientDiagnostics.CreateScope("DatabaseMigrationSqlMICollection.GetIfExists");
            scope.Start();
            try
            {
                var response = _databaseMigrationSqlMIDatabaseMigrationsSqlMIRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, managedInstanceName, targetDBName, migrationOperationId, expand, cancellationToken: cancellationToken);
                if (response.Value == null)
                    return new NoValueResponse<DatabaseMigrationSqlMIResource>(response.GetRawResponse());
                return Response.FromValue(new DatabaseMigrationSqlMIResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }
    }
}

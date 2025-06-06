// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Autorest.CSharp.Core;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager.ManagementGroups;
using Azure.ResourceManager.Resources.Models;

namespace Azure.ResourceManager.Resources
{
    /// <summary>
    /// A class representing a collection of <see cref="ArmDeploymentResource"/> and their operations.
    /// Each <see cref="ArmDeploymentResource"/> in the collection will belong to the same instance of <see cref="SubscriptionResource"/>, <see cref="ResourceGroupResource"/>, <see cref="ManagementGroupResource"/> or <see cref="TenantResource"/>.
    /// To get an <see cref="ArmDeploymentCollection"/> instance call the GetArmDeployments method from an instance of <see cref="SubscriptionResource"/>, <see cref="ResourceGroupResource"/>, <see cref="ManagementGroupResource"/> or <see cref="TenantResource"/>.
    /// </summary>
    public partial class ArmDeploymentCollection : ArmCollection, IEnumerable<ArmDeploymentResource>, IAsyncEnumerable<ArmDeploymentResource>
    {
        private readonly ClientDiagnostics _armDeploymentDeploymentsClientDiagnostics;
        private readonly DeploymentsRestOperations _armDeploymentDeploymentsRestClient;

        /// <summary> Initializes a new instance of the <see cref="ArmDeploymentCollection"/> class for mocking. </summary>
        protected ArmDeploymentCollection()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="ArmDeploymentCollection"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the parent resource that is the target of operations. </param>
        internal ArmDeploymentCollection(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _armDeploymentDeploymentsClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.Resources", ArmDeploymentResource.ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(ArmDeploymentResource.ResourceType, out string armDeploymentDeploymentsApiVersion);
            _armDeploymentDeploymentsRestClient = new DeploymentsRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, armDeploymentDeploymentsApiVersion);
        }

        /// <summary>
        /// You can provide the template and parameters directly in the request or link to JSON files.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_CreateOrUpdateAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="content"> Additional parameters supplied to the operation. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> or <paramref name="content"/> is null. </exception>
        public virtual async Task<ArmOperation<ArmDeploymentResource>> CreateOrUpdateAsync(WaitUntil waitUntil, string deploymentName, ArmDeploymentContent content, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));
            Argument.AssertNotNull(content, nameof(content));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = await _armDeploymentDeploymentsRestClient.CreateOrUpdateAtScopeAsync(Id, deploymentName, content, cancellationToken).ConfigureAwait(false);
                var operation = new ResourcesArmOperation<ArmDeploymentResource>(new ArmDeploymentOperationSource(Client), _armDeploymentDeploymentsClientDiagnostics, Pipeline, _armDeploymentDeploymentsRestClient.CreateCreateOrUpdateAtScopeRequest(Id, deploymentName, content).Request, response, OperationFinalStateVia.Location);
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
        /// You can provide the template and parameters directly in the request or link to JSON files.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_CreateOrUpdateAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="content"> Additional parameters supplied to the operation. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> or <paramref name="content"/> is null. </exception>
        public virtual ArmOperation<ArmDeploymentResource> CreateOrUpdate(WaitUntil waitUntil, string deploymentName, ArmDeploymentContent content, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));
            Argument.AssertNotNull(content, nameof(content));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = _armDeploymentDeploymentsRestClient.CreateOrUpdateAtScope(Id, deploymentName, content, cancellationToken);
                var operation = new ResourcesArmOperation<ArmDeploymentResource>(new ArmDeploymentOperationSource(Client), _armDeploymentDeploymentsClientDiagnostics, Pipeline, _armDeploymentDeploymentsRestClient.CreateCreateOrUpdateAtScopeRequest(Id, deploymentName, content).Request, response, OperationFinalStateVia.Location);
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
        /// Gets a deployment.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_GetAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> is null. </exception>
        public virtual async Task<Response<ArmDeploymentResource>> GetAsync(string deploymentName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.Get");
            scope.Start();
            try
            {
                var response = await _armDeploymentDeploymentsRestClient.GetAtScopeAsync(Id, deploymentName, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new ArmDeploymentResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets a deployment.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_GetAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> is null. </exception>
        public virtual Response<ArmDeploymentResource> Get(string deploymentName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.Get");
            scope.Start();
            try
            {
                var response = _armDeploymentDeploymentsRestClient.GetAtScope(Id, deploymentName, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new ArmDeploymentResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Get all the deployments at the given scope.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/{scope}/providers/Microsoft.Resources/deployments</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_ListAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="filter"> The filter to apply on the operation. For example, you can use $filter=provisioningState eq '{state}'. </param>
        /// <param name="top"> The number of results to get. If null is passed, returns all deployments. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> An async collection of <see cref="ArmDeploymentResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual AsyncPageable<ArmDeploymentResource> GetAllAsync(string filter = null, int? top = null, CancellationToken cancellationToken = default)
        {
            Core.HttpMessage FirstPageRequest(int? pageSizeHint) => _armDeploymentDeploymentsRestClient.CreateListAtScopeRequest(Id, filter, top);
            Core.HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _armDeploymentDeploymentsRestClient.CreateListAtScopeNextPageRequest(nextLink, Id, filter, top);
            return GeneratorPageableHelpers.CreateAsyncPageable(FirstPageRequest, NextPageRequest, e => new ArmDeploymentResource(Client, ArmDeploymentData.DeserializeArmDeploymentData(e)), _armDeploymentDeploymentsClientDiagnostics, Pipeline, "ArmDeploymentCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// Get all the deployments at the given scope.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/{scope}/providers/Microsoft.Resources/deployments</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_ListAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="filter"> The filter to apply on the operation. For example, you can use $filter=provisioningState eq '{state}'. </param>
        /// <param name="top"> The number of results to get. If null is passed, returns all deployments. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> A collection of <see cref="ArmDeploymentResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual Pageable<ArmDeploymentResource> GetAll(string filter = null, int? top = null, CancellationToken cancellationToken = default)
        {
            Core.HttpMessage FirstPageRequest(int? pageSizeHint) => _armDeploymentDeploymentsRestClient.CreateListAtScopeRequest(Id, filter, top);
            Core.HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _armDeploymentDeploymentsRestClient.CreateListAtScopeNextPageRequest(nextLink, Id, filter, top);
            return GeneratorPageableHelpers.CreatePageable(FirstPageRequest, NextPageRequest, e => new ArmDeploymentResource(Client, ArmDeploymentData.DeserializeArmDeploymentData(e)), _armDeploymentDeploymentsClientDiagnostics, Pipeline, "ArmDeploymentCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// Checks to see if the resource exists in azure.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_GetAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> is null. </exception>
        public virtual async Task<Response<bool>> ExistsAsync(string deploymentName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.Exists");
            scope.Start();
            try
            {
                var response = await _armDeploymentDeploymentsRestClient.GetAtScopeAsync(Id, deploymentName, cancellationToken: cancellationToken).ConfigureAwait(false);
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
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_GetAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> is null. </exception>
        public virtual Response<bool> Exists(string deploymentName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.Exists");
            scope.Start();
            try
            {
                var response = _armDeploymentDeploymentsRestClient.GetAtScope(Id, deploymentName, cancellationToken: cancellationToken);
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
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_GetAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> is null. </exception>
        public virtual async Task<NullableResponse<ArmDeploymentResource>> GetIfExistsAsync(string deploymentName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = await _armDeploymentDeploymentsRestClient.GetAtScopeAsync(Id, deploymentName, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    return new NoValueResponse<ArmDeploymentResource>(response.GetRawResponse());
                return Response.FromValue(new ArmDeploymentResource(Client, response.Value), response.GetRawResponse());
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
        /// <description>/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>Deployments_GetAtScope</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-04-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="ArmDeploymentResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="deploymentName"> The name of the deployment. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="deploymentName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="deploymentName"/> is null. </exception>
        public virtual NullableResponse<ArmDeploymentResource> GetIfExists(string deploymentName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(deploymentName, nameof(deploymentName));

            using var scope = _armDeploymentDeploymentsClientDiagnostics.CreateScope("ArmDeploymentCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = _armDeploymentDeploymentsRestClient.GetAtScope(Id, deploymentName, cancellationToken: cancellationToken);
                if (response.Value == null)
                    return new NoValueResponse<ArmDeploymentResource>(response.GetRawResponse());
                return Response.FromValue(new ArmDeploymentResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        IEnumerator<ArmDeploymentResource> IEnumerable<ArmDeploymentResource>.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IAsyncEnumerator<ArmDeploymentResource> IAsyncEnumerable<ArmDeploymentResource>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return GetAllAsync(cancellationToken: cancellationToken).GetAsyncEnumerator(cancellationToken);
        }
    }
}

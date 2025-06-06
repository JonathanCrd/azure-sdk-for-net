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
using Azure.ResourceManager.Resources;

namespace Azure.ResourceManager.Network
{
    /// <summary>
    /// A class representing a collection of <see cref="CustomIPPrefixResource"/> and their operations.
    /// Each <see cref="CustomIPPrefixResource"/> in the collection will belong to the same instance of <see cref="ResourceGroupResource"/>.
    /// To get a <see cref="CustomIPPrefixCollection"/> instance call the GetCustomIPPrefixes method from an instance of <see cref="ResourceGroupResource"/>.
    /// </summary>
    public partial class CustomIPPrefixCollection : ArmCollection, IEnumerable<CustomIPPrefixResource>, IAsyncEnumerable<CustomIPPrefixResource>
    {
        private readonly ClientDiagnostics _customIPPrefixClientDiagnostics;
        private readonly CustomIPPrefixesRestOperations _customIPPrefixRestClient;

        /// <summary> Initializes a new instance of the <see cref="CustomIPPrefixCollection"/> class for mocking. </summary>
        protected CustomIPPrefixCollection()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="CustomIPPrefixCollection"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the parent resource that is the target of operations. </param>
        internal CustomIPPrefixCollection(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _customIPPrefixClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.Network", CustomIPPrefixResource.ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(CustomIPPrefixResource.ResourceType, out string customIPPrefixApiVersion);
            _customIPPrefixRestClient = new CustomIPPrefixesRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, customIPPrefixApiVersion);
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
        /// Creates or updates a custom IP prefix.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_CreateOrUpdate</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="data"> Parameters supplied to the create or update custom IP prefix operation. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> or <paramref name="data"/> is null. </exception>
        public virtual async Task<ArmOperation<CustomIPPrefixResource>> CreateOrUpdateAsync(WaitUntil waitUntil, string customIPPrefixName, CustomIPPrefixData data, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));
            Argument.AssertNotNull(data, nameof(data));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = await _customIPPrefixRestClient.CreateOrUpdateAsync(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, data, cancellationToken).ConfigureAwait(false);
                var operation = new NetworkArmOperation<CustomIPPrefixResource>(new CustomIPPrefixOperationSource(Client), _customIPPrefixClientDiagnostics, Pipeline, _customIPPrefixRestClient.CreateCreateOrUpdateRequest(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, data).Request, response, OperationFinalStateVia.Location);
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
        /// Creates or updates a custom IP prefix.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_CreateOrUpdate</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="waitUntil"> <see cref="WaitUntil.Completed"/> if the method should wait to return until the long-running operation has completed on the service; <see cref="WaitUntil.Started"/> if it should return after starting the operation. For more information on long-running operations, please see <see href="https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/core/Azure.Core/samples/LongRunningOperations.md"> Azure.Core Long-Running Operation samples</see>. </param>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="data"> Parameters supplied to the create or update custom IP prefix operation. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> or <paramref name="data"/> is null. </exception>
        public virtual ArmOperation<CustomIPPrefixResource> CreateOrUpdate(WaitUntil waitUntil, string customIPPrefixName, CustomIPPrefixData data, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));
            Argument.AssertNotNull(data, nameof(data));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.CreateOrUpdate");
            scope.Start();
            try
            {
                var response = _customIPPrefixRestClient.CreateOrUpdate(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, data, cancellationToken);
                var operation = new NetworkArmOperation<CustomIPPrefixResource>(new CustomIPPrefixOperationSource(Client), _customIPPrefixClientDiagnostics, Pipeline, _customIPPrefixRestClient.CreateCreateOrUpdateRequest(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, data).Request, response, OperationFinalStateVia.Location);
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
        /// Gets the specified custom IP prefix in a specified resource group.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="expand"> Expands referenced resources. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> is null. </exception>
        public virtual async Task<Response<CustomIPPrefixResource>> GetAsync(string customIPPrefixName, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.Get");
            scope.Start();
            try
            {
                var response = await _customIPPrefixRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, expand, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new CustomIPPrefixResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets the specified custom IP prefix in a specified resource group.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="expand"> Expands referenced resources. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> is null. </exception>
        public virtual Response<CustomIPPrefixResource> Get(string customIPPrefixName, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.Get");
            scope.Start();
            try
            {
                var response = _customIPPrefixRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, expand, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new CustomIPPrefixResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets all custom IP prefixes in a resource group.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_List</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> An async collection of <see cref="CustomIPPrefixResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual AsyncPageable<CustomIPPrefixResource> GetAllAsync(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _customIPPrefixRestClient.CreateListRequest(Id.SubscriptionId, Id.ResourceGroupName);
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _customIPPrefixRestClient.CreateListNextPageRequest(nextLink, Id.SubscriptionId, Id.ResourceGroupName);
            return GeneratorPageableHelpers.CreateAsyncPageable(FirstPageRequest, NextPageRequest, e => new CustomIPPrefixResource(Client, CustomIPPrefixData.DeserializeCustomIPPrefixData(e)), _customIPPrefixClientDiagnostics, Pipeline, "CustomIPPrefixCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// Gets all custom IP prefixes in a resource group.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_List</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> A collection of <see cref="CustomIPPrefixResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual Pageable<CustomIPPrefixResource> GetAll(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => _customIPPrefixRestClient.CreateListRequest(Id.SubscriptionId, Id.ResourceGroupName);
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => _customIPPrefixRestClient.CreateListNextPageRequest(nextLink, Id.SubscriptionId, Id.ResourceGroupName);
            return GeneratorPageableHelpers.CreatePageable(FirstPageRequest, NextPageRequest, e => new CustomIPPrefixResource(Client, CustomIPPrefixData.DeserializeCustomIPPrefixData(e)), _customIPPrefixClientDiagnostics, Pipeline, "CustomIPPrefixCollection.GetAll", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// Checks to see if the resource exists in azure.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="expand"> Expands referenced resources. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> is null. </exception>
        public virtual async Task<Response<bool>> ExistsAsync(string customIPPrefixName, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.Exists");
            scope.Start();
            try
            {
                var response = await _customIPPrefixRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, expand, cancellationToken: cancellationToken).ConfigureAwait(false);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="expand"> Expands referenced resources. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> is null. </exception>
        public virtual Response<bool> Exists(string customIPPrefixName, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.Exists");
            scope.Start();
            try
            {
                var response = _customIPPrefixRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, expand, cancellationToken: cancellationToken);
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="expand"> Expands referenced resources. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> is null. </exception>
        public virtual async Task<NullableResponse<CustomIPPrefixResource>> GetIfExistsAsync(string customIPPrefixName, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = await _customIPPrefixRestClient.GetAsync(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, expand, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    return new NoValueResponse<CustomIPPrefixResource>(response.GetRawResponse());
                return Response.FromValue(new CustomIPPrefixResource(Client, response.Value), response.GetRawResponse());
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
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/customIpPrefixes/{customIpPrefixName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CustomIPPrefixes_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-07-01</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CustomIPPrefixResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="customIPPrefixName"> The name of the custom IP prefix. </param>
        /// <param name="expand"> Expands referenced resources. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentException"> <paramref name="customIPPrefixName"/> is an empty string, and was expected to be non-empty. </exception>
        /// <exception cref="ArgumentNullException"> <paramref name="customIPPrefixName"/> is null. </exception>
        public virtual NullableResponse<CustomIPPrefixResource> GetIfExists(string customIPPrefixName, string expand = null, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(customIPPrefixName, nameof(customIPPrefixName));

            using var scope = _customIPPrefixClientDiagnostics.CreateScope("CustomIPPrefixCollection.GetIfExists");
            scope.Start();
            try
            {
                var response = _customIPPrefixRestClient.Get(Id.SubscriptionId, Id.ResourceGroupName, customIPPrefixName, expand, cancellationToken: cancellationToken);
                if (response.Value == null)
                    return new NoValueResponse<CustomIPPrefixResource>(response.GetRawResponse());
                return Response.FromValue(new CustomIPPrefixResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        IEnumerator<CustomIPPrefixResource> IEnumerable<CustomIPPrefixResource>.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetAll().GetEnumerator();
        }

        IAsyncEnumerator<CustomIPPrefixResource> IAsyncEnumerable<CustomIPPrefixResource>.GetAsyncEnumerator(CancellationToken cancellationToken)
        {
            return GetAllAsync(cancellationToken: cancellationToken).GetAsyncEnumerator(cancellationToken);
        }
    }
}

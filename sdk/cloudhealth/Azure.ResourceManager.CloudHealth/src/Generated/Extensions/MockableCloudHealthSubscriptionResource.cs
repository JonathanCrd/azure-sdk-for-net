// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Threading;
using Autorest.CSharp.Core;
using Azure.Core;
using Azure.Core.Pipeline;

namespace Azure.ResourceManager.CloudHealth.Mocking
{
    /// <summary> A class to add extension methods to SubscriptionResource. </summary>
    public partial class MockableCloudHealthSubscriptionResource : ArmResource
    {
        private ClientDiagnostics _healthModelClientDiagnostics;
        private HealthModelsRestOperations _healthModelRestClient;

        /// <summary> Initializes a new instance of the <see cref="MockableCloudHealthSubscriptionResource"/> class for mocking. </summary>
        protected MockableCloudHealthSubscriptionResource()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="MockableCloudHealthSubscriptionResource"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the resource that is the target of operations. </param>
        internal MockableCloudHealthSubscriptionResource(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
        }

        private ClientDiagnostics HealthModelClientDiagnostics => _healthModelClientDiagnostics ??= new ClientDiagnostics("Azure.ResourceManager.CloudHealth", HealthModelResource.ResourceType.Namespace, Diagnostics);
        private HealthModelsRestOperations HealthModelRestClient => _healthModelRestClient ??= new HealthModelsRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, GetApiVersionOrNull(HealthModelResource.ResourceType));

        private string GetApiVersionOrNull(ResourceType resourceType)
        {
            TryGetApiVersion(resourceType, out string apiVersion);
            return apiVersion;
        }

        /// <summary>
        /// List HealthModel resources by subscription ID
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Microsoft.CloudHealth/healthmodels</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>HealthModel_ListBySubscription</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-05-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="HealthModelResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> An async collection of <see cref="HealthModelResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual AsyncPageable<HealthModelResource> GetHealthModelsAsync(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => HealthModelRestClient.CreateListBySubscriptionRequest(Id.SubscriptionId);
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => HealthModelRestClient.CreateListBySubscriptionNextPageRequest(nextLink, Id.SubscriptionId);
            return GeneratorPageableHelpers.CreateAsyncPageable(FirstPageRequest, NextPageRequest, e => new HealthModelResource(Client, HealthModelData.DeserializeHealthModelData(e)), HealthModelClientDiagnostics, Pipeline, "MockableCloudHealthSubscriptionResource.GetHealthModels", "value", "nextLink", cancellationToken);
        }

        /// <summary>
        /// List HealthModel resources by subscription ID
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Microsoft.CloudHealth/healthmodels</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>HealthModel_ListBySubscription</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-05-01-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="HealthModelResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <returns> A collection of <see cref="HealthModelResource"/> that may take multiple service requests to iterate over. </returns>
        public virtual Pageable<HealthModelResource> GetHealthModels(CancellationToken cancellationToken = default)
        {
            HttpMessage FirstPageRequest(int? pageSizeHint) => HealthModelRestClient.CreateListBySubscriptionRequest(Id.SubscriptionId);
            HttpMessage NextPageRequest(int? pageSizeHint, string nextLink) => HealthModelRestClient.CreateListBySubscriptionNextPageRequest(nextLink, Id.SubscriptionId);
            return GeneratorPageableHelpers.CreatePageable(FirstPageRequest, NextPageRequest, e => new HealthModelResource(Client, HealthModelData.DeserializeHealthModelData(e)), HealthModelClientDiagnostics, Pipeline, "MockableCloudHealthSubscriptionResource.GetHealthModels", "value", "nextLink", cancellationToken);
        }
    }
}

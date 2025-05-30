// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.ResourceManager.OnlineExperimentation.Mocking;
using Azure.ResourceManager.Resources;

namespace Azure.ResourceManager.OnlineExperimentation
{
    /// <summary> A class to add extension methods to Azure.ResourceManager.OnlineExperimentation. </summary>
    public static partial class OnlineExperimentationExtensions
    {
        private static MockableOnlineExperimentationArmClient GetMockableOnlineExperimentationArmClient(ArmClient client)
        {
            return client.GetCachedClient(client0 => new MockableOnlineExperimentationArmClient(client0));
        }

        private static MockableOnlineExperimentationResourceGroupResource GetMockableOnlineExperimentationResourceGroupResource(ArmResource resource)
        {
            return resource.GetCachedClient(client => new MockableOnlineExperimentationResourceGroupResource(client, resource.Id));
        }

        private static MockableOnlineExperimentationSubscriptionResource GetMockableOnlineExperimentationSubscriptionResource(ArmResource resource)
        {
            return resource.GetCachedClient(client => new MockableOnlineExperimentationSubscriptionResource(client, resource.Id));
        }

        /// <summary>
        /// Gets an object representing an <see cref="OnlineExperimentationWorkspaceResource" /> along with the instance operations that can be performed on it but with no data.
        /// You can use <see cref="OnlineExperimentationWorkspaceResource.CreateResourceIdentifier" /> to create an <see cref="OnlineExperimentationWorkspaceResource" /> <see cref="ResourceIdentifier" /> from its components.
        /// <item>
        /// <term>Mocking</term>
        /// <description>To mock this method, please mock <see cref="MockableOnlineExperimentationArmClient.GetOnlineExperimentationWorkspaceResource(ResourceIdentifier)"/> instead.</description>
        /// </item>
        /// </summary>
        /// <param name="client"> The <see cref="ArmClient" /> instance the method will execute against. </param>
        /// <param name="id"> The resource ID of the resource to get. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="client"/> is null. </exception>
        /// <returns> Returns a <see cref="OnlineExperimentationWorkspaceResource"/> object. </returns>
        public static OnlineExperimentationWorkspaceResource GetOnlineExperimentationWorkspaceResource(this ArmClient client, ResourceIdentifier id)
        {
            Argument.AssertNotNull(client, nameof(client));

            return GetMockableOnlineExperimentationArmClient(client).GetOnlineExperimentationWorkspaceResource(id);
        }

        /// <summary>
        /// Gets a collection of OnlineExperimentationWorkspaceResources in the ResourceGroupResource.
        /// <item>
        /// <term>Mocking</term>
        /// <description>To mock this method, please mock <see cref="MockableOnlineExperimentationResourceGroupResource.GetOnlineExperimentationWorkspaces()"/> instead.</description>
        /// </item>
        /// </summary>
        /// <param name="resourceGroupResource"> The <see cref="ResourceGroupResource" /> instance the method will execute against. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="resourceGroupResource"/> is null. </exception>
        /// <returns> An object representing collection of OnlineExperimentationWorkspaceResources and their operations over a OnlineExperimentationWorkspaceResource. </returns>
        public static OnlineExperimentationWorkspaceCollection GetOnlineExperimentationWorkspaces(this ResourceGroupResource resourceGroupResource)
        {
            Argument.AssertNotNull(resourceGroupResource, nameof(resourceGroupResource));

            return GetMockableOnlineExperimentationResourceGroupResource(resourceGroupResource).GetOnlineExperimentationWorkspaces();
        }

        /// <summary>
        /// Gets an online experimentation workspace.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OnlineExperimentation/workspaces/{workspaceName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>OnlineExperimentationWorkspace_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-05-31-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="OnlineExperimentationWorkspaceResource"/></description>
        /// </item>
        /// </list>
        /// <item>
        /// <term>Mocking</term>
        /// <description>To mock this method, please mock <see cref="MockableOnlineExperimentationResourceGroupResource.GetOnlineExperimentationWorkspaceAsync(string,CancellationToken)"/> instead.</description>
        /// </item>
        /// </summary>
        /// <param name="resourceGroupResource"> The <see cref="ResourceGroupResource" /> instance the method will execute against. </param>
        /// <param name="workspaceName"> The name of the OnlineExperimentationWorkspace. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="resourceGroupResource"/> or <paramref name="workspaceName"/> is null. </exception>
        /// <exception cref="ArgumentException"> <paramref name="workspaceName"/> is an empty string, and was expected to be non-empty. </exception>
        [ForwardsClientCalls]
        public static async Task<Response<OnlineExperimentationWorkspaceResource>> GetOnlineExperimentationWorkspaceAsync(this ResourceGroupResource resourceGroupResource, string workspaceName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(resourceGroupResource, nameof(resourceGroupResource));

            return await GetMockableOnlineExperimentationResourceGroupResource(resourceGroupResource).GetOnlineExperimentationWorkspaceAsync(workspaceName, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Gets an online experimentation workspace.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.OnlineExperimentation/workspaces/{workspaceName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>OnlineExperimentationWorkspace_Get</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-05-31-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="OnlineExperimentationWorkspaceResource"/></description>
        /// </item>
        /// </list>
        /// <item>
        /// <term>Mocking</term>
        /// <description>To mock this method, please mock <see cref="MockableOnlineExperimentationResourceGroupResource.GetOnlineExperimentationWorkspace(string,CancellationToken)"/> instead.</description>
        /// </item>
        /// </summary>
        /// <param name="resourceGroupResource"> The <see cref="ResourceGroupResource" /> instance the method will execute against. </param>
        /// <param name="workspaceName"> The name of the OnlineExperimentationWorkspace. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="resourceGroupResource"/> or <paramref name="workspaceName"/> is null. </exception>
        /// <exception cref="ArgumentException"> <paramref name="workspaceName"/> is an empty string, and was expected to be non-empty. </exception>
        [ForwardsClientCalls]
        public static Response<OnlineExperimentationWorkspaceResource> GetOnlineExperimentationWorkspace(this ResourceGroupResource resourceGroupResource, string workspaceName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(resourceGroupResource, nameof(resourceGroupResource));

            return GetMockableOnlineExperimentationResourceGroupResource(resourceGroupResource).GetOnlineExperimentationWorkspace(workspaceName, cancellationToken);
        }

        /// <summary>
        /// Gets all online experimentation workspaces in the specified subscription.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Microsoft.OnlineExperimentation/workspaces</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>OnlineExperimentationWorkspace_ListBySubscription</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-05-31-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="OnlineExperimentationWorkspaceResource"/></description>
        /// </item>
        /// </list>
        /// <item>
        /// <term>Mocking</term>
        /// <description>To mock this method, please mock <see cref="MockableOnlineExperimentationSubscriptionResource.GetOnlineExperimentationWorkspaces(CancellationToken)"/> instead.</description>
        /// </item>
        /// </summary>
        /// <param name="subscriptionResource"> The <see cref="SubscriptionResource" /> instance the method will execute against. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="subscriptionResource"/> is null. </exception>
        /// <returns> An async collection of <see cref="OnlineExperimentationWorkspaceResource"/> that may take multiple service requests to iterate over. </returns>
        public static AsyncPageable<OnlineExperimentationWorkspaceResource> GetOnlineExperimentationWorkspacesAsync(this SubscriptionResource subscriptionResource, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(subscriptionResource, nameof(subscriptionResource));

            return GetMockableOnlineExperimentationSubscriptionResource(subscriptionResource).GetOnlineExperimentationWorkspacesAsync(cancellationToken);
        }

        /// <summary>
        /// Gets all online experimentation workspaces in the specified subscription.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Microsoft.OnlineExperimentation/workspaces</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>OnlineExperimentationWorkspace_ListBySubscription</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2025-05-31-preview</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="OnlineExperimentationWorkspaceResource"/></description>
        /// </item>
        /// </list>
        /// <item>
        /// <term>Mocking</term>
        /// <description>To mock this method, please mock <see cref="MockableOnlineExperimentationSubscriptionResource.GetOnlineExperimentationWorkspaces(CancellationToken)"/> instead.</description>
        /// </item>
        /// </summary>
        /// <param name="subscriptionResource"> The <see cref="SubscriptionResource" /> instance the method will execute against. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="subscriptionResource"/> is null. </exception>
        /// <returns> A collection of <see cref="OnlineExperimentationWorkspaceResource"/> that may take multiple service requests to iterate over. </returns>
        public static Pageable<OnlineExperimentationWorkspaceResource> GetOnlineExperimentationWorkspaces(this SubscriptionResource subscriptionResource, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNull(subscriptionResource, nameof(subscriptionResource));

            return GetMockableOnlineExperimentationSubscriptionResource(subscriptionResource).GetOnlineExperimentationWorkspaces(cancellationToken);
        }
    }
}

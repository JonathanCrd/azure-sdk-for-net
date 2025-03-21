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

namespace Azure.ResourceManager.Compute
{
    /// <summary>
    /// A Class representing a CloudServiceOSVersion along with the instance operations that can be performed on it.
    /// If you have a <see cref="ResourceIdentifier"/> you can construct a <see cref="CloudServiceOSVersionResource"/>
    /// from an instance of <see cref="ArmClient"/> using the GetCloudServiceOSVersionResource method.
    /// Otherwise you can get one from its parent resource <see cref="SubscriptionResource"/> using the GetCloudServiceOSVersion method.
    /// </summary>
    public partial class CloudServiceOSVersionResource : ArmResource
    {
        /// <summary> Generate the resource identifier of a <see cref="CloudServiceOSVersionResource"/> instance. </summary>
        /// <param name="subscriptionId"> The subscriptionId. </param>
        /// <param name="location"> The location. </param>
        /// <param name="osVersionName"> The osVersionName. </param>
        public static ResourceIdentifier CreateResourceIdentifier(string subscriptionId, AzureLocation location, string osVersionName)
        {
            var resourceId = $"/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/cloudServiceOsVersions/{osVersionName}";
            return new ResourceIdentifier(resourceId);
        }

        private readonly ClientDiagnostics _cloudServiceOSVersionCloudServiceOperatingSystemsClientDiagnostics;
        private readonly CloudServiceOperatingSystemsRestOperations _cloudServiceOSVersionCloudServiceOperatingSystemsRestClient;
        private readonly CloudServiceOSVersionData _data;

        /// <summary> Gets the resource type for the operations. </summary>
        public static readonly ResourceType ResourceType = "Microsoft.Compute/locations/cloudServiceOsVersions";

        /// <summary> Initializes a new instance of the <see cref="CloudServiceOSVersionResource"/> class for mocking. </summary>
        protected CloudServiceOSVersionResource()
        {
        }

        /// <summary> Initializes a new instance of the <see cref="CloudServiceOSVersionResource"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="data"> The resource that is the target of operations. </param>
        internal CloudServiceOSVersionResource(ArmClient client, CloudServiceOSVersionData data) : this(client, data.Id)
        {
            HasData = true;
            _data = data;
        }

        /// <summary> Initializes a new instance of the <see cref="CloudServiceOSVersionResource"/> class. </summary>
        /// <param name="client"> The client parameters to use in these operations. </param>
        /// <param name="id"> The identifier of the resource that is the target of operations. </param>
        internal CloudServiceOSVersionResource(ArmClient client, ResourceIdentifier id) : base(client, id)
        {
            _cloudServiceOSVersionCloudServiceOperatingSystemsClientDiagnostics = new ClientDiagnostics("Azure.ResourceManager.Compute", ResourceType.Namespace, Diagnostics);
            TryGetApiVersion(ResourceType, out string cloudServiceOSVersionCloudServiceOperatingSystemsApiVersion);
            _cloudServiceOSVersionCloudServiceOperatingSystemsRestClient = new CloudServiceOperatingSystemsRestOperations(Pipeline, Diagnostics.ApplicationId, Endpoint, cloudServiceOSVersionCloudServiceOperatingSystemsApiVersion);
#if DEBUG
			ValidateResourceId(Id);
#endif
        }

        /// <summary> Gets whether or not the current instance has data. </summary>
        public virtual bool HasData { get; }

        /// <summary> Gets the data representing this Feature. </summary>
        /// <exception cref="InvalidOperationException"> Throws if there is no data loaded in the current instance. </exception>
        public virtual CloudServiceOSVersionData Data
        {
            get
            {
                if (!HasData)
                    throw new InvalidOperationException("The current instance does not have data, you must call Get first.");
                return _data;
            }
        }

        internal static void ValidateResourceId(ResourceIdentifier id)
        {
            if (id.ResourceType != ResourceType)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Invalid resource type {0} expected {1}", id.ResourceType, ResourceType), nameof(id));
        }

        /// <summary>
        /// Gets properties of a guest operating system version that can be specified in the XML service configuration (.cscfg) for a cloud service.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/cloudServiceOsVersions/{osVersionName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CloudServiceOperatingSystems_GetOSVersion</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-04</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CloudServiceOSVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual async Task<Response<CloudServiceOSVersionResource>> GetAsync(CancellationToken cancellationToken = default)
        {
            using var scope = _cloudServiceOSVersionCloudServiceOperatingSystemsClientDiagnostics.CreateScope("CloudServiceOSVersionResource.Get");
            scope.Start();
            try
            {
                var response = await _cloudServiceOSVersionCloudServiceOperatingSystemsRestClient.GetOSVersionAsync(Id.SubscriptionId, new AzureLocation(Id.Parent.Name), Id.Name, cancellationToken).ConfigureAwait(false);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new CloudServiceOSVersionResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }

        /// <summary>
        /// Gets properties of a guest operating system version that can be specified in the XML service configuration (.cscfg) for a cloud service.
        /// <list type="bullet">
        /// <item>
        /// <term>Request Path</term>
        /// <description>/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/cloudServiceOsVersions/{osVersionName}</description>
        /// </item>
        /// <item>
        /// <term>Operation Id</term>
        /// <description>CloudServiceOperatingSystems_GetOSVersion</description>
        /// </item>
        /// <item>
        /// <term>Default Api Version</term>
        /// <description>2024-11-04</description>
        /// </item>
        /// <item>
        /// <term>Resource</term>
        /// <description><see cref="CloudServiceOSVersionResource"/></description>
        /// </item>
        /// </list>
        /// </summary>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        public virtual Response<CloudServiceOSVersionResource> Get(CancellationToken cancellationToken = default)
        {
            using var scope = _cloudServiceOSVersionCloudServiceOperatingSystemsClientDiagnostics.CreateScope("CloudServiceOSVersionResource.Get");
            scope.Start();
            try
            {
                var response = _cloudServiceOSVersionCloudServiceOperatingSystemsRestClient.GetOSVersion(Id.SubscriptionId, new AzureLocation(Id.Parent.Name), Id.Name, cancellationToken);
                if (response.Value == null)
                    throw new RequestFailedException(response.GetRawResponse());
                return Response.FromValue(new CloudServiceOSVersionResource(Client, response.Value), response.GetRawResponse());
            }
            catch (Exception e)
            {
                scope.Failed(e);
                throw;
            }
        }
    }
}

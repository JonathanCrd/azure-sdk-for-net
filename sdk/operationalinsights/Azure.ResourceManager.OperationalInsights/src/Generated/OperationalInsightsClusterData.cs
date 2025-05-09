// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure.Core;
using Azure.ResourceManager.Models;
using Azure.ResourceManager.OperationalInsights.Models;

namespace Azure.ResourceManager.OperationalInsights
{
    /// <summary>
    /// A class representing the OperationalInsightsCluster data model.
    /// The top level Log Analytics cluster resource container.
    /// </summary>
    public partial class OperationalInsightsClusterData : TrackedResourceData
    {
        /// <summary>
        /// Keeps track of any properties unknown to the library.
        /// <para>
        /// To assign an object to the value of this property use <see cref="BinaryData.FromObjectAsJson{T}(T, System.Text.Json.JsonSerializerOptions?)"/>.
        /// </para>
        /// <para>
        /// To assign an already formatted json string to this property use <see cref="BinaryData.FromString(string)"/>.
        /// </para>
        /// <para>
        /// Examples:
        /// <list type="bullet">
        /// <item>
        /// <term>BinaryData.FromObjectAsJson("foo")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("\"foo\"")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromObjectAsJson(new { key = "value" })</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("{\"key\": \"value\"}")</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// </list>
        /// </para>
        /// </summary>
        private IDictionary<string, BinaryData> _serializedAdditionalRawData;

        /// <summary> Initializes a new instance of <see cref="OperationalInsightsClusterData"/>. </summary>
        /// <param name="location"> The location. </param>
        public OperationalInsightsClusterData(AzureLocation location) : base(location)
        {
            AssociatedWorkspaces = new ChangeTrackingList<OperationalInsightsClusterAssociatedWorkspace>();
        }

        /// <summary> Initializes a new instance of <see cref="OperationalInsightsClusterData"/>. </summary>
        /// <param name="id"> The id. </param>
        /// <param name="name"> The name. </param>
        /// <param name="resourceType"> The resourceType. </param>
        /// <param name="systemData"> The systemData. </param>
        /// <param name="tags"> The tags. </param>
        /// <param name="location"> The location. </param>
        /// <param name="identity"> Resource's identity. </param>
        /// <param name="sku"> The sku properties. </param>
        /// <param name="clusterId"> The ID associated with the cluster. </param>
        /// <param name="provisioningState"> The provisioning state of the cluster. </param>
        /// <param name="isDoubleEncryptionEnabled"> Configures whether cluster will use double encryption. This Property can not be modified after cluster creation. Default value is 'true'. </param>
        /// <param name="isAvailabilityZonesEnabled"> Sets whether the cluster will support availability zones. This can be set as true only in regions where Azure Data Explorer support Availability Zones. This Property can not be modified after cluster creation. Default value is 'true' if region supports Availability Zones. </param>
        /// <param name="billingType"> The cluster's billing type. </param>
        /// <param name="keyVaultProperties"> The associated key properties. </param>
        /// <param name="lastModifiedOn"> The last time the cluster was updated. </param>
        /// <param name="createdOn"> The cluster creation time. </param>
        /// <param name="associatedWorkspaces"> The list of Log Analytics workspaces associated with the cluster. </param>
        /// <param name="capacityReservationProperties"> Additional properties for capacity reservation. </param>
        /// <param name="replication"> Cluster's replication properties. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal OperationalInsightsClusterData(ResourceIdentifier id, string name, ResourceType resourceType, SystemData systemData, IDictionary<string, string> tags, AzureLocation location, ManagedServiceIdentity identity, OperationalInsightsClusterSku sku, Guid? clusterId, OperationalInsightsClusterEntityStatus? provisioningState, bool? isDoubleEncryptionEnabled, bool? isAvailabilityZonesEnabled, OperationalInsightsBillingType? billingType, OperationalInsightsKeyVaultProperties keyVaultProperties, DateTimeOffset? lastModifiedOn, DateTimeOffset? createdOn, IList<OperationalInsightsClusterAssociatedWorkspace> associatedWorkspaces, OperationalInsightsCapacityReservationProperties capacityReservationProperties, OperationalInsightsClusterReplicationProperties replication, IDictionary<string, BinaryData> serializedAdditionalRawData) : base(id, name, resourceType, systemData, tags, location)
        {
            Identity = identity;
            Sku = sku;
            ClusterId = clusterId;
            ProvisioningState = provisioningState;
            IsDoubleEncryptionEnabled = isDoubleEncryptionEnabled;
            IsAvailabilityZonesEnabled = isAvailabilityZonesEnabled;
            BillingType = billingType;
            KeyVaultProperties = keyVaultProperties;
            LastModifiedOn = lastModifiedOn;
            CreatedOn = createdOn;
            AssociatedWorkspaces = associatedWorkspaces;
            CapacityReservationProperties = capacityReservationProperties;
            Replication = replication;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Initializes a new instance of <see cref="OperationalInsightsClusterData"/> for deserialization. </summary>
        internal OperationalInsightsClusterData()
        {
        }

        /// <summary> Resource's identity. </summary>
        [WirePath("identity")]
        public ManagedServiceIdentity Identity { get; set; }
        /// <summary> The sku properties. </summary>
        [WirePath("sku")]
        public OperationalInsightsClusterSku Sku { get; set; }
        /// <summary> The ID associated with the cluster. </summary>
        [WirePath("properties.clusterId")]
        public Guid? ClusterId { get; }
        /// <summary> The provisioning state of the cluster. </summary>
        [WirePath("properties.provisioningState")]
        public OperationalInsightsClusterEntityStatus? ProvisioningState { get; }
        /// <summary> Configures whether cluster will use double encryption. This Property can not be modified after cluster creation. Default value is 'true'. </summary>
        [WirePath("properties.isDoubleEncryptionEnabled")]
        public bool? IsDoubleEncryptionEnabled { get; set; }
        /// <summary> Sets whether the cluster will support availability zones. This can be set as true only in regions where Azure Data Explorer support Availability Zones. This Property can not be modified after cluster creation. Default value is 'true' if region supports Availability Zones. </summary>
        [WirePath("properties.isAvailabilityZonesEnabled")]
        public bool? IsAvailabilityZonesEnabled { get; set; }
        /// <summary> The cluster's billing type. </summary>
        [WirePath("properties.billingType")]
        public OperationalInsightsBillingType? BillingType { get; set; }
        /// <summary> The associated key properties. </summary>
        [WirePath("properties.keyVaultProperties")]
        public OperationalInsightsKeyVaultProperties KeyVaultProperties { get; set; }
        /// <summary> The last time the cluster was updated. </summary>
        [WirePath("properties.lastModifiedDate")]
        public DateTimeOffset? LastModifiedOn { get; }
        /// <summary> The cluster creation time. </summary>
        [WirePath("properties.createdDate")]
        public DateTimeOffset? CreatedOn { get; }
        /// <summary> The list of Log Analytics workspaces associated with the cluster. </summary>
        [WirePath("properties.associatedWorkspaces")]
        public IList<OperationalInsightsClusterAssociatedWorkspace> AssociatedWorkspaces { get; }
        /// <summary> Additional properties for capacity reservation. </summary>
        [WirePath("properties.capacityReservationProperties")]
        public OperationalInsightsCapacityReservationProperties CapacityReservationProperties { get; set; }
        /// <summary> Cluster's replication properties. </summary>
        [WirePath("properties.replication")]
        public OperationalInsightsClusterReplicationProperties Replication { get; set; }
    }
}

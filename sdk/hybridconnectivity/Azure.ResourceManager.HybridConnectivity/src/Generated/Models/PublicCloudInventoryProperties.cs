// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure.Core;

namespace Azure.ResourceManager.HybridConnectivity.Models
{
    /// <summary> Definition of inventory. </summary>
    public partial class PublicCloudInventoryProperties
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

        /// <summary> Initializes a new instance of <see cref="PublicCloudInventoryProperties"/>. </summary>
        internal PublicCloudInventoryProperties()
        {
        }

        /// <summary> Initializes a new instance of <see cref="PublicCloudInventoryProperties"/>. </summary>
        /// <param name="cloudNativeType"> Gets or sets the cloud native resource type. </param>
        /// <param name="cloudNativeResourceId"> Gets or sets the cloud native resource name. </param>
        /// <param name="azureResourceId"> Gets or sets the mapped azure resource id. </param>
        /// <param name="status"> Gets or sets the status of the inventory. </param>
        /// <param name="statusDetails"> Gets or sets the status details. </param>
        /// <param name="provisioningState"> The resource provisioning state. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal PublicCloudInventoryProperties(CloudNativeType? cloudNativeType, string cloudNativeResourceId, ResourceIdentifier azureResourceId, PublicCloudConnectorSolutionConfigurationStatus? status, string statusDetails, PublicCloudResourceProvisioningState? provisioningState, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            CloudNativeType = cloudNativeType;
            CloudNativeResourceId = cloudNativeResourceId;
            AzureResourceId = azureResourceId;
            Status = status;
            StatusDetails = statusDetails;
            ProvisioningState = provisioningState;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Gets or sets the cloud native resource type. </summary>
        public CloudNativeType? CloudNativeType { get; }
        /// <summary> Gets or sets the cloud native resource name. </summary>
        public string CloudNativeResourceId { get; }
        /// <summary> Gets or sets the mapped azure resource id. </summary>
        public ResourceIdentifier AzureResourceId { get; }
        /// <summary> Gets or sets the status of the inventory. </summary>
        public PublicCloudConnectorSolutionConfigurationStatus? Status { get; }
        /// <summary> Gets or sets the status details. </summary>
        public string StatusDetails { get; }
        /// <summary> The resource provisioning state. </summary>
        public PublicCloudResourceProvisioningState? ProvisioningState { get; }
    }
}

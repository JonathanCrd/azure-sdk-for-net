// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.RecoveryServicesSiteRecovery.Models
{
    /// <summary> Input definition for unplanned failover input properties. </summary>
    public partial class ClusterUnplannedFailoverContentProperties
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

        /// <summary> Initializes a new instance of <see cref="ClusterUnplannedFailoverContentProperties"/>. </summary>
        public ClusterUnplannedFailoverContentProperties()
        {
        }

        /// <summary> Initializes a new instance of <see cref="ClusterUnplannedFailoverContentProperties"/>. </summary>
        /// <param name="failoverDirection"> Failover direction. </param>
        /// <param name="sourceSiteOperations"> Source site operations status. </param>
        /// <param name="providerSpecificDetails">
        /// Provider specific settings.
        /// Please note <see cref="ClusterUnplannedFailoverProviderSpecificContent"/> is the base class. According to the scenario, a derived class of the base class might need to be assigned here, or this property needs to be casted to one of the possible derived classes.
        /// The available derived classes include <see cref="A2AClusterUnplannedFailoverContent"/>.
        /// </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal ClusterUnplannedFailoverContentProperties(string failoverDirection, string sourceSiteOperations, ClusterUnplannedFailoverProviderSpecificContent providerSpecificDetails, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            FailoverDirection = failoverDirection;
            SourceSiteOperations = sourceSiteOperations;
            ProviderSpecificDetails = providerSpecificDetails;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Failover direction. </summary>
        public string FailoverDirection { get; set; }
        /// <summary> Source site operations status. </summary>
        public string SourceSiteOperations { get; set; }
        /// <summary>
        /// Provider specific settings.
        /// Please note <see cref="ClusterUnplannedFailoverProviderSpecificContent"/> is the base class. According to the scenario, a derived class of the base class might need to be assigned here, or this property needs to be casted to one of the possible derived classes.
        /// The available derived classes include <see cref="A2AClusterUnplannedFailoverContent"/>.
        /// </summary>
        public ClusterUnplannedFailoverProviderSpecificContent ProviderSpecificDetails { get; set; }
    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.Playwright.Models
{
    /// <summary> Subscription-level location-based Playwright quota resource properties. </summary>
    public partial class PlaywrightQuotaProperties
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

        /// <summary> Initializes a new instance of <see cref="PlaywrightQuotaProperties"/>. </summary>
        internal PlaywrightQuotaProperties()
        {
        }

        /// <summary> Initializes a new instance of <see cref="PlaywrightQuotaProperties"/>. </summary>
        /// <param name="freeTrial"> The subscription-level location-based Playwright quota resource free-trial properties. </param>
        /// <param name="provisioningState"> The status of the last resource operation. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal PlaywrightQuotaProperties(PlaywrightFreeTrialProperties freeTrial, PlaywrightProvisioningState? provisioningState, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            FreeTrial = freeTrial;
            ProvisioningState = provisioningState;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> The subscription-level location-based Playwright quota resource free-trial properties. </summary>
        public PlaywrightFreeTrialProperties FreeTrial { get; }
        /// <summary> The status of the last resource operation. </summary>
        public PlaywrightProvisioningState? ProvisioningState { get; }
    }
}

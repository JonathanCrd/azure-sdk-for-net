// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.Billing.Models
{
    /// <summary> Request parameters to initiate partner transfer. </summary>
    public partial class PartnerTransferDetailCreateOrUpdateContent
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

        /// <summary> Initializes a new instance of <see cref="PartnerTransferDetailCreateOrUpdateContent"/>. </summary>
        public PartnerTransferDetailCreateOrUpdateContent()
        {
        }

        /// <summary> Initializes a new instance of <see cref="PartnerTransferDetailCreateOrUpdateContent"/>. </summary>
        /// <param name="recipientEmailId"> The email ID of the recipient to whom the transfer request is sent. </param>
        /// <param name="resellerId"> Optional MPN ID of the reseller for transfer requests that are sent from a Microsoft Partner Agreement billing account. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal PartnerTransferDetailCreateOrUpdateContent(string recipientEmailId, string resellerId, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            RecipientEmailId = recipientEmailId;
            ResellerId = resellerId;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> The email ID of the recipient to whom the transfer request is sent. </summary>
        [WirePath("properties.recipientEmailId")]
        public string RecipientEmailId { get; set; }
        /// <summary> Optional MPN ID of the reseller for transfer requests that are sent from a Microsoft Partner Agreement billing account. </summary>
        [WirePath("properties.resellerId")]
        public string ResellerId { get; set; }
    }
}

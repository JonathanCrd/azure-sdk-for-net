// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.Messaging.EventGrid.SystemEvents
{
    /// <summary> Schema of the Data property of an EventGridEvent for MQTT Client state changes. </summary>
    public partial class EventGridMqttClientEventData
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
        private protected IDictionary<string, BinaryData> _serializedAdditionalRawData;

        /// <summary> Initializes a new instance of <see cref="EventGridMqttClientEventData"/>. </summary>
        /// <param name="clientAuthenticationName">
        /// Unique identifier for the MQTT client that the client presents to the service
        /// for authentication. This case-sensitive string can be up to 128 characters
        /// long, and supports UTF-8 characters.
        /// </param>
        /// <param name="namespaceName"> Name of the Event Grid namespace where the MQTT client was created or updated. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="clientAuthenticationName"/> or <paramref name="namespaceName"/> is null. </exception>
        internal EventGridMqttClientEventData(string clientAuthenticationName, string namespaceName)
        {
            Argument.AssertNotNull(clientAuthenticationName, nameof(clientAuthenticationName));
            Argument.AssertNotNull(namespaceName, nameof(namespaceName));

            ClientAuthenticationName = clientAuthenticationName;
            NamespaceName = namespaceName;
        }

        /// <summary> Initializes a new instance of <see cref="EventGridMqttClientEventData"/>. </summary>
        /// <param name="clientAuthenticationName">
        /// Unique identifier for the MQTT client that the client presents to the service
        /// for authentication. This case-sensitive string can be up to 128 characters
        /// long, and supports UTF-8 characters.
        /// </param>
        /// <param name="clientName"> Name of the client resource in the Event Grid namespace. </param>
        /// <param name="namespaceName"> Name of the Event Grid namespace where the MQTT client was created or updated. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal EventGridMqttClientEventData(string clientAuthenticationName, string clientName, string namespaceName, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            ClientAuthenticationName = clientAuthenticationName;
            ClientName = clientName;
            NamespaceName = namespaceName;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Initializes a new instance of <see cref="EventGridMqttClientEventData"/> for deserialization. </summary>
        internal EventGridMqttClientEventData()
        {
        }

        /// <summary>
        /// Unique identifier for the MQTT client that the client presents to the service
        /// for authentication. This case-sensitive string can be up to 128 characters
        /// long, and supports UTF-8 characters.
        /// </summary>
        public string ClientAuthenticationName { get; }
        /// <summary> Name of the client resource in the Event Grid namespace. </summary>
        public string ClientName { get; }
        /// <summary> Name of the Event Grid namespace where the MQTT client was created or updated. </summary>
        public string NamespaceName { get; }
    }
}

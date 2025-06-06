// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.Messaging.EventGrid.SystemEvents
{
    /// <summary> Identifies a participant in Azure Communication services. A participant is, for example, a phone number or an Azure communication user. This model must be interpreted as a union: Apart from rawId, at most one further property may be set. </summary>
    public partial class CommunicationIdentifierModel
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

        /// <summary> Initializes a new instance of <see cref="CommunicationIdentifierModel"/>. </summary>
        /// <param name="rawId"> Raw Id of the identifier. Optional in requests, required in responses. </param>
        /// <param name="communicationUser"> The communication user. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="rawId"/> or <paramref name="communicationUser"/> is null. </exception>
        internal CommunicationIdentifierModel(string rawId, CommunicationUserIdentifierModel communicationUser)
        {
            Argument.AssertNotNull(rawId, nameof(rawId));
            Argument.AssertNotNull(communicationUser, nameof(communicationUser));

            RawId = rawId;
            CommunicationUser = communicationUser;
        }

        /// <summary> Initializes a new instance of <see cref="CommunicationIdentifierModel"/>. </summary>
        /// <param name="kind"> The identifier kind. Only required in responses. </param>
        /// <param name="rawId"> Raw Id of the identifier. Optional in requests, required in responses. </param>
        /// <param name="communicationUser"> The communication user. </param>
        /// <param name="phoneNumber"> The phone number. </param>
        /// <param name="microsoftTeamsUser"> The Microsoft Teams user. </param>
        /// <param name="microsoftTeamsApp"> The Microsoft Teams application. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal CommunicationIdentifierModel(AcsCommunicationIdentifierKind? kind, string rawId, CommunicationUserIdentifierModel communicationUser, PhoneNumberIdentifierModel phoneNumber, MicrosoftTeamsUserIdentifierModel microsoftTeamsUser, AcsMicrosoftTeamsAppIdentifier microsoftTeamsApp, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            Kind = kind;
            RawId = rawId;
            CommunicationUser = communicationUser;
            PhoneNumber = phoneNumber;
            MicrosoftTeamsUser = microsoftTeamsUser;
            MicrosoftTeamsApp = microsoftTeamsApp;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Initializes a new instance of <see cref="CommunicationIdentifierModel"/> for deserialization. </summary>
        internal CommunicationIdentifierModel()
        {
        }

        /// <summary> The identifier kind. Only required in responses. </summary>
        public AcsCommunicationIdentifierKind? Kind { get; }
        /// <summary> Raw Id of the identifier. Optional in requests, required in responses. </summary>
        public string RawId { get; }
        /// <summary> The communication user. </summary>
        public CommunicationUserIdentifierModel CommunicationUser { get; }
        /// <summary> The phone number. </summary>
        public PhoneNumberIdentifierModel PhoneNumber { get; }
        /// <summary> The Microsoft Teams user. </summary>
        public MicrosoftTeamsUserIdentifierModel MicrosoftTeamsUser { get; }
        /// <summary> The Microsoft Teams application. </summary>
        public AcsMicrosoftTeamsAppIdentifier MicrosoftTeamsApp { get; }
    }
}

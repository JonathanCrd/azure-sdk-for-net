// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.AI.Language.Conversations.Models
{
    /// <summary>
    /// This is the base class of an intent prediction
    /// Please note <see cref="TargetIntentResult"/> is the base class. According to the scenario, a derived class of the base class might need to be assigned here, or this property needs to be casted to one of the possible derived classes.
    /// The available derived classes include <see cref="ConversationTargetIntentResult"/>, <see cref="LuisTargetIntentResult"/>, <see cref="NoneLinkedTargetIntentResult"/> and <see cref="QuestionAnsweringTargetIntentResult"/>.
    /// </summary>
    public abstract partial class TargetIntentResult
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

        /// <summary> Initializes a new instance of <see cref="TargetIntentResult"/>. </summary>
        /// <param name="confidence"> The prediction score and it ranges from 0.0 to 1.0. </param>
        protected TargetIntentResult(double confidence)
        {
            Confidence = confidence;
        }

        /// <summary> Initializes a new instance of <see cref="TargetIntentResult"/>. </summary>
        /// <param name="targetProjectKind"> This is the base class of an intent prediction. </param>
        /// <param name="apiVersion"> The API version used to call a target service. </param>
        /// <param name="confidence"> The prediction score and it ranges from 0.0 to 1.0. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal TargetIntentResult(TargetProjectKind targetProjectKind, string apiVersion, double confidence, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            TargetProjectKind = targetProjectKind;
            ApiVersion = apiVersion;
            Confidence = confidence;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Initializes a new instance of <see cref="TargetIntentResult"/> for deserialization. </summary>
        internal TargetIntentResult()
        {
        }

        /// <summary> This is the base class of an intent prediction. </summary>
        internal TargetProjectKind TargetProjectKind { get; set; }
        /// <summary> The API version used to call a target service. </summary>
        public string ApiVersion { get; }
        /// <summary> The prediction score and it ranges from 0.0 to 1.0. </summary>
        public double Confidence { get; }
    }
}

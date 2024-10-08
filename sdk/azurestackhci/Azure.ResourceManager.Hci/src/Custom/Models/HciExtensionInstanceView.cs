// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Azure.ResourceManager.Hci.Models
{
    /// <summary> Describes the Extension Instance View. </summary>
    [Obsolete("This class is now deprecated. Please use the new class `ArcExtensionInstanceView` moving forward.")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    public partial class HciExtensionInstanceView
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

        /// <summary> Initializes a new instance of <see cref="HciExtensionInstanceView"/>. </summary>
        internal HciExtensionInstanceView()
        {
        }

        /// <summary> Initializes a new instance of <see cref="HciExtensionInstanceView"/>. </summary>
        /// <param name="name"> The extension name. </param>
        /// <param name="extensionInstanceViewType"> Specifies the type of the extension; an example is "MicrosoftMonitoringAgent". </param>
        /// <param name="typeHandlerVersion"> Specifies the version of the script handler. </param>
        /// <param name="status"> Instance view status. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal HciExtensionInstanceView(string name, string extensionInstanceViewType, string typeHandlerVersion, ExtensionInstanceViewStatus status, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            Name = name;
            ExtensionInstanceViewType = extensionInstanceViewType;
            TypeHandlerVersion = typeHandlerVersion;
            Status = status;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> The extension name. </summary>
        public string Name { get; }
        /// <summary> Specifies the type of the extension; an example is "MicrosoftMonitoringAgent". </summary>
        public string ExtensionInstanceViewType { get; }
        /// <summary> Specifies the version of the script handler. </summary>
        public string TypeHandlerVersion { get; }
        /// <summary> Instance view status. </summary>
        public ExtensionInstanceViewStatus Status { get; }
    }
}

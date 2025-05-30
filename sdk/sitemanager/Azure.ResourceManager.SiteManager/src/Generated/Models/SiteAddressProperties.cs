// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.SiteManager.Models
{
    /// <summary> Site address properties. </summary>
    public partial class SiteAddressProperties
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

        /// <summary> Initializes a new instance of <see cref="SiteAddressProperties"/>. </summary>
        public SiteAddressProperties()
        {
        }

        /// <summary> Initializes a new instance of <see cref="SiteAddressProperties"/>. </summary>
        /// <param name="streetAddress1"> First line of the street address. </param>
        /// <param name="streetAddress2"> Second line of the street address. </param>
        /// <param name="city"> City of the address. </param>
        /// <param name="stateOrProvince"> State or province of the address. </param>
        /// <param name="country"> Country of the address. </param>
        /// <param name="postalCode"> Postal or ZIP code of the address. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal SiteAddressProperties(string streetAddress1, string streetAddress2, string city, string stateOrProvince, string country, string postalCode, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            StreetAddress1 = streetAddress1;
            StreetAddress2 = streetAddress2;
            City = city;
            StateOrProvince = stateOrProvince;
            Country = country;
            PostalCode = postalCode;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> First line of the street address. </summary>
        public string StreetAddress1 { get; set; }
        /// <summary> Second line of the street address. </summary>
        public string StreetAddress2 { get; set; }
        /// <summary> City of the address. </summary>
        public string City { get; set; }
        /// <summary> State or province of the address. </summary>
        public string StateOrProvince { get; set; }
        /// <summary> Country of the address. </summary>
        public string Country { get; set; }
        /// <summary> Postal or ZIP code of the address. </summary>
        public string PostalCode { get; set; }
    }
}

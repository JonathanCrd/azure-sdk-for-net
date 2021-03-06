// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Management.DevTestLabs.Models
{
    using Microsoft.Rest;
    using Microsoft.Rest.Serialization;
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// A secret.
    /// </summary>
    [Rest.Serialization.JsonTransformation]
    public partial class SecretFragment : UpdateResource
    {
        /// <summary>
        /// Initializes a new instance of the SecretFragment class.
        /// </summary>
        public SecretFragment()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the SecretFragment class.
        /// </summary>
        /// <param name="tags">The tags of the resource.</param>
        /// <param name="value">The value of the secret for secret
        /// creation.</param>
        public SecretFragment(IDictionary<string, string> tags = default(IDictionary<string, string>), string value = default(string))
            : base(tags)
        {
            Value = value;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets the value of the secret for secret creation.
        /// </summary>
        [JsonProperty(PropertyName = "properties.value")]
        public string Value { get; set; }

    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;

namespace Azure.ResourceManager.RecoveryServicesSiteRecovery.Models
{
    /// <summary> VMwareCbt specific resume replication input. </summary>
    public partial class VMwareCbtResumeReplicationContent : ResumeReplicationProviderSpecificContent
    {
        /// <summary> Initializes a new instance of <see cref="VMwareCbtResumeReplicationContent"/>. </summary>
        public VMwareCbtResumeReplicationContent()
        {
            InstanceType = "VMwareCbt";
        }

        /// <summary> Initializes a new instance of <see cref="VMwareCbtResumeReplicationContent"/>. </summary>
        /// <param name="instanceType"> The class type. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        /// <param name="deleteMigrationResources"> A value indicating whether Migration resources to be deleted. </param>
        internal VMwareCbtResumeReplicationContent(string instanceType, IDictionary<string, BinaryData> serializedAdditionalRawData, string deleteMigrationResources) : base(instanceType, serializedAdditionalRawData)
        {
            DeleteMigrationResources = deleteMigrationResources;
            InstanceType = instanceType ?? "VMwareCbt";
        }

        /// <summary> A value indicating whether Migration resources to be deleted. </summary>
        public string DeleteMigrationResources { get; set; }
    }
}

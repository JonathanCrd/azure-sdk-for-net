// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure.Core;
using Azure.ResourceManager.CosmosDBForPostgreSql.Models;
using Azure.ResourceManager.Models;

namespace Azure.ResourceManager.CosmosDBForPostgreSql
{
    /// <summary>
    /// A class representing the CosmosDBForPostgreSqlClusterServer data model.
    /// Represents a server in a cluster.
    /// </summary>
    public partial class CosmosDBForPostgreSqlClusterServerData : ResourceData
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

        /// <summary> Initializes a new instance of <see cref="CosmosDBForPostgreSqlClusterServerData"/>. </summary>
        public CosmosDBForPostgreSqlClusterServerData()
        {
        }

        /// <summary> Initializes a new instance of <see cref="CosmosDBForPostgreSqlClusterServerData"/>. </summary>
        /// <param name="id"> The id. </param>
        /// <param name="name"> The name. </param>
        /// <param name="resourceType"> The resourceType. </param>
        /// <param name="systemData"> The systemData. </param>
        /// <param name="serverEdition"> The edition of a server. </param>
        /// <param name="storageQuotaInMb"> The storage of a server in MB. </param>
        /// <param name="vCores"> The vCores count of a server. </param>
        /// <param name="isHAEnabled"> If high availability (HA) is enabled or not for the server. </param>
        /// <param name="isPublicIPAccessEnabled"> If public access is enabled on server. </param>
        /// <param name="isReadOnly"> If server database is set to read-only by system maintenance depending on high disk space usage. </param>
        /// <param name="administratorLogin"> The administrator's login name of the servers in the cluster. </param>
        /// <param name="fullyQualifiedDomainName"> The fully qualified domain name of a server. </param>
        /// <param name="role"> The role of server in the cluster. </param>
        /// <param name="state"> A state of a cluster/server that is visible to user. </param>
        /// <param name="haState"> A state of HA feature for the cluster. </param>
        /// <param name="availabilityZone"> Availability Zone information of the server. </param>
        /// <param name="postgresqlVersion"> The major PostgreSQL version of server. </param>
        /// <param name="citusVersion"> The Citus extension version of server. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal CosmosDBForPostgreSqlClusterServerData(ResourceIdentifier id, string name, ResourceType resourceType, SystemData systemData, string serverEdition, int? storageQuotaInMb, int? vCores, bool? isHAEnabled, bool? isPublicIPAccessEnabled, bool? isReadOnly, string administratorLogin, string fullyQualifiedDomainName, CosmosDBForPostgreSqlServerRole? role, string state, string haState, string availabilityZone, string postgresqlVersion, string citusVersion, IDictionary<string, BinaryData> serializedAdditionalRawData) : base(id, name, resourceType, systemData)
        {
            ServerEdition = serverEdition;
            StorageQuotaInMb = storageQuotaInMb;
            VCores = vCores;
            IsHAEnabled = isHAEnabled;
            IsPublicIPAccessEnabled = isPublicIPAccessEnabled;
            IsReadOnly = isReadOnly;
            AdministratorLogin = administratorLogin;
            FullyQualifiedDomainName = fullyQualifiedDomainName;
            Role = role;
            State = state;
            HaState = haState;
            AvailabilityZone = availabilityZone;
            PostgresqlVersion = postgresqlVersion;
            CitusVersion = citusVersion;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> The edition of a server. </summary>
        public string ServerEdition { get; set; }
        /// <summary> The storage of a server in MB. </summary>
        public int? StorageQuotaInMb { get; set; }
        /// <summary> The vCores count of a server. </summary>
        public int? VCores { get; set; }
        /// <summary> If high availability (HA) is enabled or not for the server. </summary>
        public bool? IsHAEnabled { get; set; }
        /// <summary> If public access is enabled on server. </summary>
        public bool? IsPublicIPAccessEnabled { get; }
        /// <summary> If server database is set to read-only by system maintenance depending on high disk space usage. </summary>
        public bool? IsReadOnly { get; }
        /// <summary> The administrator's login name of the servers in the cluster. </summary>
        public string AdministratorLogin { get; }
        /// <summary> The fully qualified domain name of a server. </summary>
        public string FullyQualifiedDomainName { get; }
        /// <summary> The role of server in the cluster. </summary>
        public CosmosDBForPostgreSqlServerRole? Role { get; set; }
        /// <summary> A state of a cluster/server that is visible to user. </summary>
        public string State { get; }
        /// <summary> A state of HA feature for the cluster. </summary>
        public string HaState { get; }
        /// <summary> Availability Zone information of the server. </summary>
        public string AvailabilityZone { get; set; }
        /// <summary> The major PostgreSQL version of server. </summary>
        public string PostgresqlVersion { get; set; }
        /// <summary> The Citus extension version of server. </summary>
        public string CitusVersion { get; set; }
    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure.Core;
using Azure.ResourceManager.Models;
using Azure.ResourceManager.Sql.Models;

namespace Azure.ResourceManager.Sql
{
    /// <summary>
    /// A class representing the SqlServer data model.
    /// An Azure SQL Database server.
    /// </summary>
    public partial class SqlServerData : TrackedResourceData
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

        /// <summary> Initializes a new instance of <see cref="SqlServerData"/>. </summary>
        /// <param name="location"> The location. </param>
        public SqlServerData(AzureLocation location) : base(location)
        {
            PrivateEndpointConnections = new ChangeTrackingList<SqlServerPrivateEndpointConnection>();
        }

        /// <summary> Initializes a new instance of <see cref="SqlServerData"/>. </summary>
        /// <param name="id"> The id. </param>
        /// <param name="name"> The name. </param>
        /// <param name="resourceType"> The resourceType. </param>
        /// <param name="systemData"> The systemData. </param>
        /// <param name="tags"> The tags. </param>
        /// <param name="location"> The location. </param>
        /// <param name="identity"> The Azure Active Directory identity of the server. </param>
        /// <param name="kind"> Kind of sql server. This is metadata used for the Azure portal experience. </param>
        /// <param name="administratorLogin"> Administrator username for the server. Once created it cannot be changed. </param>
        /// <param name="administratorLoginPassword"> The administrator login password (required for server creation). </param>
        /// <param name="version"> The version of the server. </param>
        /// <param name="state"> The state of the server. </param>
        /// <param name="fullyQualifiedDomainName"> The fully qualified domain name of the server. </param>
        /// <param name="privateEndpointConnections"> List of private endpoint connections on a server. </param>
        /// <param name="minTlsVersion"> Minimal TLS version. Allowed values: 'None', 1.0', '1.1', '1.2', '1.3'. </param>
        /// <param name="publicNetworkAccess"> Whether or not public endpoint access is allowed for this server.  Value is optional but if passed in, must be 'Enabled' or 'Disabled' or 'SecuredByPerimeter'. </param>
        /// <param name="workspaceFeature"> Whether or not existing server has a workspace created and if it allows connection from workspace. </param>
        /// <param name="primaryUserAssignedIdentityId"> The resource id of a user assigned identity to be used by default. </param>
        /// <param name="federatedClientId"> The Client id used for cross tenant CMK scenario. </param>
        /// <param name="keyId"> A CMK URI of the key to use for encryption. </param>
        /// <param name="administrators"> The Azure Active Directory administrator can be utilized during server creation and for server updates, except for the azureADOnlyAuthentication property. To update the azureADOnlyAuthentication property, individual API must be used. </param>
        /// <param name="restrictOutboundNetworkAccess"> Whether or not to restrict outbound network access for this server.  Value is optional but if passed in, must be 'Enabled' or 'Disabled'. </param>
        /// <param name="isIPv6Enabled"> Whether or not to enable IPv6 support for this server.  Value is optional but if passed in, must be 'Enabled' or 'Disabled'. </param>
        /// <param name="externalGovernanceStatus"> Status of external governance. </param>
        /// <param name="retentionDays"> Number of days this server will stay soft-deleted. </param>
        /// <param name="createMode"> Create mode for server, only valid values for this are Normal and Restore. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal SqlServerData(ResourceIdentifier id, string name, ResourceType resourceType, SystemData systemData, IDictionary<string, string> tags, AzureLocation location, ManagedServiceIdentity identity, string kind, string administratorLogin, string administratorLoginPassword, string version, string state, string fullyQualifiedDomainName, IReadOnlyList<SqlServerPrivateEndpointConnection> privateEndpointConnections, SqlMinimalTlsVersion? minTlsVersion, ServerNetworkAccessFlag? publicNetworkAccess, ServerWorkspaceFeature? workspaceFeature, ResourceIdentifier primaryUserAssignedIdentityId, Guid? federatedClientId, Uri keyId, ServerExternalAdministrator administrators, ServerNetworkAccessFlag? restrictOutboundNetworkAccess, ServerNetworkAccessFlag? isIPv6Enabled, ExternalGovernanceStatus? externalGovernanceStatus, int? retentionDays, SqlServerCreateMode? createMode, IDictionary<string, BinaryData> serializedAdditionalRawData) : base(id, name, resourceType, systemData, tags, location)
        {
            Identity = identity;
            Kind = kind;
            AdministratorLogin = administratorLogin;
            AdministratorLoginPassword = administratorLoginPassword;
            Version = version;
            State = state;
            FullyQualifiedDomainName = fullyQualifiedDomainName;
            PrivateEndpointConnections = privateEndpointConnections;
            MinTlsVersion = minTlsVersion;
            PublicNetworkAccess = publicNetworkAccess;
            WorkspaceFeature = workspaceFeature;
            PrimaryUserAssignedIdentityId = primaryUserAssignedIdentityId;
            FederatedClientId = federatedClientId;
            KeyId = keyId;
            Administrators = administrators;
            RestrictOutboundNetworkAccess = restrictOutboundNetworkAccess;
            IsIPv6Enabled = isIPv6Enabled;
            ExternalGovernanceStatus = externalGovernanceStatus;
            RetentionDays = retentionDays;
            CreateMode = createMode;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Initializes a new instance of <see cref="SqlServerData"/> for deserialization. </summary>
        internal SqlServerData()
        {
        }

        /// <summary> The Azure Active Directory identity of the server. </summary>
        [WirePath("identity")]
        public ManagedServiceIdentity Identity { get; set; }
        /// <summary> Kind of sql server. This is metadata used for the Azure portal experience. </summary>
        [WirePath("kind")]
        public string Kind { get; }
        /// <summary> Administrator username for the server. Once created it cannot be changed. </summary>
        [WirePath("properties.administratorLogin")]
        public string AdministratorLogin { get; set; }
        /// <summary> The administrator login password (required for server creation). </summary>
        [WirePath("properties.administratorLoginPassword")]
        public string AdministratorLoginPassword { get; set; }
        /// <summary> The version of the server. </summary>
        [WirePath("properties.version")]
        public string Version { get; set; }
        /// <summary> The state of the server. </summary>
        [WirePath("properties.state")]
        public string State { get; }
        /// <summary> The fully qualified domain name of the server. </summary>
        [WirePath("properties.fullyQualifiedDomainName")]
        public string FullyQualifiedDomainName { get; }
        /// <summary> List of private endpoint connections on a server. </summary>
        [WirePath("properties.privateEndpointConnections")]
        public IReadOnlyList<SqlServerPrivateEndpointConnection> PrivateEndpointConnections { get; }
        /// <summary> Minimal TLS version. Allowed values: 'None', 1.0', '1.1', '1.2', '1.3'. </summary>
        [WirePath("properties.minimalTlsVersion")]
        public SqlMinimalTlsVersion? MinTlsVersion { get; set; }
        /// <summary> Whether or not public endpoint access is allowed for this server.  Value is optional but if passed in, must be 'Enabled' or 'Disabled' or 'SecuredByPerimeter'. </summary>
        [WirePath("properties.publicNetworkAccess")]
        public ServerNetworkAccessFlag? PublicNetworkAccess { get; set; }
        /// <summary> Whether or not existing server has a workspace created and if it allows connection from workspace. </summary>
        [WirePath("properties.workspaceFeature")]
        public ServerWorkspaceFeature? WorkspaceFeature { get; }
        /// <summary> The resource id of a user assigned identity to be used by default. </summary>
        [WirePath("properties.primaryUserAssignedIdentityId")]
        public ResourceIdentifier PrimaryUserAssignedIdentityId { get; set; }
        /// <summary> The Client id used for cross tenant CMK scenario. </summary>
        [WirePath("properties.federatedClientId")]
        public Guid? FederatedClientId { get; set; }
        /// <summary> A CMK URI of the key to use for encryption. </summary>
        [WirePath("properties.keyId")]
        public Uri KeyId { get; set; }
        /// <summary> The Azure Active Directory administrator can be utilized during server creation and for server updates, except for the azureADOnlyAuthentication property. To update the azureADOnlyAuthentication property, individual API must be used. </summary>
        [WirePath("properties.administrators")]
        public ServerExternalAdministrator Administrators { get; set; }
        /// <summary> Whether or not to restrict outbound network access for this server.  Value is optional but if passed in, must be 'Enabled' or 'Disabled'. </summary>
        [WirePath("properties.restrictOutboundNetworkAccess")]
        public ServerNetworkAccessFlag? RestrictOutboundNetworkAccess { get; set; }
        /// <summary> Whether or not to enable IPv6 support for this server.  Value is optional but if passed in, must be 'Enabled' or 'Disabled'. </summary>
        [WirePath("properties.isIPv6Enabled")]
        public ServerNetworkAccessFlag? IsIPv6Enabled { get; set; }
        /// <summary> Status of external governance. </summary>
        [WirePath("properties.externalGovernanceStatus")]
        public ExternalGovernanceStatus? ExternalGovernanceStatus { get; }
        /// <summary> Number of days this server will stay soft-deleted. </summary>
        [WirePath("properties.retentionDays")]
        public int? RetentionDays { get; set; }
        /// <summary> Create mode for server, only valid values for this are Normal and Restore. </summary>
        [WirePath("properties.createMode")]
        public SqlServerCreateMode? CreateMode { get; set; }
    }
}

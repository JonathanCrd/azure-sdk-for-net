// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable enable

using Azure.Core;
using Azure.Provisioning.Primitives;
using Azure.Provisioning.Resources;
using System;

namespace Azure.Provisioning.ContainerRegistry;

/// <summary>
/// ContainerRegistryPrivateEndpointConnection.
/// </summary>
public partial class ContainerRegistryPrivateEndpointConnection : Resource
{
    /// <summary>
    /// The name of the private endpoint connection.
    /// </summary>
    public BicepValue<string> Name { get => _name; set => _name.Assign(value); }
    private readonly BicepValue<string> _name;

    /// <summary>
    /// A collection of information about the state of the connection between
    /// service consumer and provider.
    /// </summary>
    public BicepValue<ContainerRegistryPrivateLinkServiceConnectionState> ConnectionState { get => _connectionState; set => _connectionState.Assign(value); }
    private readonly BicepValue<ContainerRegistryPrivateLinkServiceConnectionState> _connectionState;

    /// <summary>
    /// Gets or sets Id.
    /// </summary>
    public BicepValue<ResourceIdentifier> PrivateEndpointId { get => _privateEndpointId; set => _privateEndpointId.Assign(value); }
    private readonly BicepValue<ResourceIdentifier> _privateEndpointId;

    /// <summary>
    /// Gets the Id.
    /// </summary>
    public BicepValue<ResourceIdentifier> Id { get => _id; }
    private readonly BicepValue<ResourceIdentifier> _id;

    /// <summary>
    /// The provisioning state of private endpoint connection resource.
    /// </summary>
    public BicepValue<ContainerRegistryProvisioningState> ProvisioningState { get => _provisioningState; }
    private readonly BicepValue<ContainerRegistryProvisioningState> _provisioningState;

    /// <summary>
    /// Gets the SystemData.
    /// </summary>
    public BicepValue<SystemData> SystemData { get => _systemData; }
    private readonly BicepValue<SystemData> _systemData;

    /// <summary>
    /// Gets or sets a reference to the parent ContainerRegistryService.
    /// </summary>
    public ContainerRegistryService? Parent { get => _parent!.Value; set => _parent!.Value = value; }
    private readonly ResourceReference<ContainerRegistryService> _parent;

    /// <summary>
    /// Creates a new ContainerRegistryPrivateEndpointConnection.
    /// </summary>
    /// <param name="resourceName">Name of the ContainerRegistryPrivateEndpointConnection.</param>
    /// <param name="resourceVersion">Version of the ContainerRegistryPrivateEndpointConnection.</param>
    /// <param name="context">Provisioning context for this resource.</param>
    public ContainerRegistryPrivateEndpointConnection(string resourceName, string? resourceVersion = default, ProvisioningContext? context = default)
        : base(resourceName, "Microsoft.ContainerRegistry/registries/privateEndpointConnections", resourceVersion ?? "2023-07-01", context)
    {
        _name = BicepValue<string>.DefineProperty(this, "Name", ["name"], isRequired: true);
        _connectionState = BicepValue<ContainerRegistryPrivateLinkServiceConnectionState>.DefineProperty(this, "ConnectionState", ["properties", "privateLinkServiceConnectionState"]);
        _privateEndpointId = BicepValue<ResourceIdentifier>.DefineProperty(this, "PrivateEndpointId", ["properties", "privateEndpoint", "id"]);
        _id = BicepValue<ResourceIdentifier>.DefineProperty(this, "Id", ["id"], isOutput: true);
        _provisioningState = BicepValue<ContainerRegistryProvisioningState>.DefineProperty(this, "ProvisioningState", ["properties", "provisioningState"], isOutput: true);
        _systemData = BicepValue<SystemData>.DefineProperty(this, "SystemData", ["systemData"], isOutput: true);
        _parent = ResourceReference<ContainerRegistryService>.DefineResource(this, "Parent", ["parent"], isRequired: true);
    }

    /// <summary>
    /// Supported ContainerRegistryPrivateEndpointConnection resource versions.
    /// </summary>
    public static class ResourceVersions
    {
        /// <summary>
        /// 2023-11-01-preview.
        /// </summary>
        public static readonly string V2023_11_01_preview = "2023-11-01-preview";

        /// <summary>
        /// 2023-07-01.
        /// </summary>
        public static readonly string V2023_07_01 = "2023-07-01";

        /// <summary>
        /// 2022-12-01.
        /// </summary>
        public static readonly string V2022_12_01 = "2022-12-01";

        /// <summary>
        /// 2021-09-01.
        /// </summary>
        public static readonly string V2021_09_01 = "2021-09-01";
    }

    /// <summary>
    /// Creates a reference to an existing
    /// ContainerRegistryPrivateEndpointConnection.
    /// </summary>
    /// <param name="resourceName">Name of the ContainerRegistryPrivateEndpointConnection.</param>
    /// <param name="resourceVersion">Version of the ContainerRegistryPrivateEndpointConnection.</param>
    /// <returns>The existing ContainerRegistryPrivateEndpointConnection resource.</returns>
    public static ContainerRegistryPrivateEndpointConnection FromExisting(string resourceName, string? resourceVersion = default) =>
        new(resourceName, resourceVersion) { IsExistingResource = true };
}

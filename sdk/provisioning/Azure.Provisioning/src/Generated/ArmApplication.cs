// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable enable

using Azure.Core;
using Azure.Provisioning;
using Azure.Provisioning.Primitives;
using System;

namespace Azure.Provisioning.Resources;

/// <summary>
/// ArmApplication.
/// </summary>
public partial class ArmApplication : ProvisionableResource
{
    /// <summary>
    /// The name of the managed application.
    /// </summary>
    public BicepValue<string> Name 
    {
        get { Initialize(); return _name!; }
        set { Initialize(); _name!.Assign(value); }
    }
    private BicepValue<string>? _name;

    /// <summary>
    /// The kind of the managed application. Allowed values are MarketPlace and
    /// ServiceCatalog.
    /// </summary>
    public BicepValue<string> Kind 
    {
        get { Initialize(); return _kind!; }
        set { Initialize(); _kind!.Assign(value); }
    }
    private BicepValue<string>? _kind;

    /// <summary>
    /// Gets or sets the Location.
    /// </summary>
    public BicepValue<AzureLocation> Location 
    {
        get { Initialize(); return _location!; }
        set { Initialize(); _location!.Assign(value); }
    }
    private BicepValue<AzureLocation>? _location;

    /// <summary>
    /// The fully qualified path of managed application definition Id.
    /// </summary>
    public BicepValue<ResourceIdentifier> ApplicationDefinitionId 
    {
        get { Initialize(); return _applicationDefinitionId!; }
        set { Initialize(); _applicationDefinitionId!.Assign(value); }
    }
    private BicepValue<ResourceIdentifier>? _applicationDefinitionId;

    /// <summary>
    /// The identity of the resource.
    /// </summary>
    public ArmApplicationManagedIdentity Identity 
    {
        get { Initialize(); return _identity!; }
        set { Initialize(); AssignOrReplace(ref _identity, value); }
    }
    private ArmApplicationManagedIdentity? _identity;

    /// <summary>
    /// The managed application Jit access policy.
    /// </summary>
    public ArmApplicationJitAccessPolicy JitAccessPolicy 
    {
        get { Initialize(); return _jitAccessPolicy!; }
        set { Initialize(); AssignOrReplace(ref _jitAccessPolicy, value); }
    }
    private ArmApplicationJitAccessPolicy? _jitAccessPolicy;

    /// <summary>
    /// ID of the resource that manages this resource.
    /// </summary>
    public BicepValue<string> ManagedBy 
    {
        get { Initialize(); return _managedBy!; }
        set { Initialize(); _managedBy!.Assign(value); }
    }
    private BicepValue<string>? _managedBy;

    /// <summary>
    /// The managed resource group Id.
    /// </summary>
    public BicepValue<ResourceIdentifier> ManagedResourceGroupId 
    {
        get { Initialize(); return _managedResourceGroupId!; }
        set { Initialize(); _managedResourceGroupId!.Assign(value); }
    }
    private BicepValue<ResourceIdentifier>? _managedResourceGroupId;

    /// <summary>
    /// Name and value pairs that define the managed application parameters. It
    /// can be a JObject or a well formed JSON string.
    /// To assign an object to this property use
    /// System.BinaryData.FromObjectAsJson``1(``0,System.Text.Json.JsonSerializerOptions).
    /// To assign an already formatted json string to
    /// this property use System.BinaryData.FromString(System.String).
    /// Examples:
    /// BinaryData.FromObjectAsJson(&quot;foo&quot;)Creates a
    /// payload of
    /// &quot;foo&quot;.BinaryData.FromString(&quot;\&quot;foo\&quot;&quot;)Creates
    /// a payload of &quot;foo&quot;.BinaryData.FromObjectAsJson(new { key =
    /// &quot;value&quot; })Creates a payload of { &quot;key&quot;:
    /// &quot;value&quot; }.BinaryData.FromString(&quot;{\&quot;key\&quot;:
    /// \&quot;value\&quot;}&quot;)Creates a payload of { &quot;key&quot;:
    /// &quot;value&quot; }.
    /// </summary>
    public BicepValue<BinaryData> Parameters 
    {
        get { Initialize(); return _parameters!; }
        set { Initialize(); _parameters!.Assign(value); }
    }
    private BicepValue<BinaryData>? _parameters;

    /// <summary>
    /// The plan information.
    /// </summary>
    public ArmPlan Plan 
    {
        get { Initialize(); return _plan!; }
        set { Initialize(); AssignOrReplace(ref _plan, value); }
    }
    private ArmPlan? _plan;

    /// <summary>
    /// The SKU of the resource.
    /// </summary>
    public ArmApplicationSku Sku 
    {
        get { Initialize(); return _sku!; }
        set { Initialize(); AssignOrReplace(ref _sku, value); }
    }
    private ArmApplicationSku? _sku;

    /// <summary>
    /// Gets or sets the Tags.
    /// </summary>
    public BicepDictionary<string> Tags 
    {
        get { Initialize(); return _tags!; }
        set { Initialize(); _tags!.Assign(value); }
    }
    private BicepDictionary<string>? _tags;

    /// <summary>
    /// The collection of managed application artifacts.
    /// </summary>
    public BicepList<ArmApplicationArtifact> Artifacts 
    {
        get { Initialize(); return _artifacts!; }
    }
    private BicepList<ArmApplicationArtifact>? _artifacts;

    /// <summary>
    /// The  read-only authorizations property that is retrieved from the
    /// application package.
    /// </summary>
    public BicepList<ArmApplicationAuthorization> Authorizations 
    {
        get { Initialize(); return _authorizations!; }
    }
    private BicepList<ArmApplicationAuthorization>? _authorizations;

    /// <summary>
    /// The managed application resource usage Id.
    /// </summary>
    public BicepValue<string> BillingDetailsResourceUsageId 
    {
        get { Initialize(); return _billingDetailsResourceUsageId!; }
    }
    private BicepValue<string>? _billingDetailsResourceUsageId;

    /// <summary>
    /// The client entity that created the JIT request.
    /// </summary>
    public ArmApplicationDetails CreatedBy 
    {
        get { Initialize(); return _createdBy!; }
    }
    private ArmApplicationDetails? _createdBy;

    /// <summary>
    /// The read-only customer support property that is retrieved from the
    /// application package.
    /// </summary>
    public ArmApplicationPackageContact CustomerSupport 
    {
        get { Initialize(); return _customerSupport!; }
    }
    private ArmApplicationPackageContact? _customerSupport;

    /// <summary>
    /// Gets the Id.
    /// </summary>
    public BicepValue<ResourceIdentifier> Id 
    {
        get { Initialize(); return _id!; }
    }
    private BicepValue<ResourceIdentifier>? _id;

    /// <summary>
    /// The managed application management mode.
    /// </summary>
    public BicepValue<ArmApplicationManagementMode> ManagementMode 
    {
        get { Initialize(); return _managementMode!; }
    }
    private BicepValue<ArmApplicationManagementMode>? _managementMode;

    /// <summary>
    /// Name and value pairs that define the managed application outputs.
    /// To assign an object to this property use
    /// System.BinaryData.FromObjectAsJson``1(``0,System.Text.Json.JsonSerializerOptions).
    /// To assign an already formatted json string to
    /// this property use System.BinaryData.FromString(System.String).
    /// Examples:
    /// BinaryData.FromObjectAsJson(&quot;foo&quot;)Creates a
    /// payload of
    /// &quot;foo&quot;.BinaryData.FromString(&quot;\&quot;foo\&quot;&quot;)Creates
    /// a payload of &quot;foo&quot;.BinaryData.FromObjectAsJson(new { key =
    /// &quot;value&quot; })Creates a payload of { &quot;key&quot;:
    /// &quot;value&quot; }.BinaryData.FromString(&quot;{\&quot;key\&quot;:
    /// \&quot;value\&quot;}&quot;)Creates a payload of { &quot;key&quot;:
    /// &quot;value&quot; }.
    /// </summary>
    public BicepValue<BinaryData> Outputs 
    {
        get { Initialize(); return _outputs!; }
    }
    private BicepValue<BinaryData>? _outputs;

    /// <summary>
    /// The managed application provisioning state.
    /// </summary>
    public BicepValue<ResourcesProvisioningState> ProvisioningState 
    {
        get { Initialize(); return _provisioningState!; }
    }
    private BicepValue<ResourcesProvisioningState>? _provisioningState;

    /// <summary>
    /// The publisher tenant Id.
    /// </summary>
    public BicepValue<Guid> PublisherTenantId 
    {
        get { Initialize(); return _publisherTenantId!; }
    }
    private BicepValue<Guid>? _publisherTenantId;

    /// <summary>
    /// The read-only support URLs property that is retrieved from the
    /// application package.
    /// </summary>
    public ArmApplicationPackageSupportUris SupportUris 
    {
        get { Initialize(); return _supportUris!; }
    }
    private ArmApplicationPackageSupportUris? _supportUris;

    /// <summary>
    /// Gets the SystemData.
    /// </summary>
    public SystemData SystemData 
    {
        get { Initialize(); return _systemData!; }
    }
    private SystemData? _systemData;

    /// <summary>
    /// The client entity that last updated the JIT request.
    /// </summary>
    public ArmApplicationDetails UpdatedBy 
    {
        get { Initialize(); return _updatedBy!; }
    }
    private ArmApplicationDetails? _updatedBy;

    /// <summary>
    /// Creates a new ArmApplication.
    /// </summary>
    /// <param name="bicepIdentifier">
    /// The the Bicep identifier name of the ArmApplication resource.  This can
    /// be used to refer to the resource in expressions, but is not the Azure
    /// name of the resource.  This value can contain letters, numbers, and
    /// underscores.
    /// </param>
    /// <param name="resourceVersion">Version of the ArmApplication.</param>
    public ArmApplication(string bicepIdentifier, string? resourceVersion = default)
        : base(bicepIdentifier, "Microsoft.Solutions/applications", resourceVersion ?? "2021-07-01")
    {
    }

    /// <summary>
    /// Define all the provisionable properties of ArmApplication.
    /// </summary>
    protected override void DefineProvisionableProperties()
    {
        base.DefineProvisionableProperties();
        _name = DefineProperty<string>("Name", ["name"], isRequired: true);
        _kind = DefineProperty<string>("Kind", ["kind"], isRequired: true);
        _location = DefineProperty<AzureLocation>("Location", ["location"], isRequired: true);
        _applicationDefinitionId = DefineProperty<ResourceIdentifier>("ApplicationDefinitionId", ["properties", "applicationDefinitionId"]);
        _identity = DefineModelProperty<ArmApplicationManagedIdentity>("Identity", ["identity"]);
        _jitAccessPolicy = DefineModelProperty<ArmApplicationJitAccessPolicy>("JitAccessPolicy", ["properties", "jitAccessPolicy"]);
        _managedBy = DefineProperty<string>("ManagedBy", ["managedBy"]);
        _managedResourceGroupId = DefineProperty<ResourceIdentifier>("ManagedResourceGroupId", ["properties", "managedResourceGroupId"]);
        _parameters = DefineProperty<BinaryData>("Parameters", ["properties", "parameters"]);
        _plan = DefineModelProperty<ArmPlan>("Plan", ["plan"]);
        _sku = DefineModelProperty<ArmApplicationSku>("Sku", ["sku"]);
        _tags = DefineDictionaryProperty<string>("Tags", ["tags"]);
        _artifacts = DefineListProperty<ArmApplicationArtifact>("Artifacts", ["properties", "artifacts"], isOutput: true);
        _authorizations = DefineListProperty<ArmApplicationAuthorization>("Authorizations", ["properties", "authorizations"], isOutput: true);
        _billingDetailsResourceUsageId = DefineProperty<string>("BillingDetailsResourceUsageId", ["properties", "billingDetails", "resourceUsageId"], isOutput: true);
        _createdBy = DefineModelProperty<ArmApplicationDetails>("CreatedBy", ["properties", "createdBy"], isOutput: true);
        _customerSupport = DefineModelProperty<ArmApplicationPackageContact>("CustomerSupport", ["properties", "customerSupport"], isOutput: true);
        _id = DefineProperty<ResourceIdentifier>("Id", ["id"], isOutput: true);
        _managementMode = DefineProperty<ArmApplicationManagementMode>("ManagementMode", ["properties", "managementMode"], isOutput: true);
        _outputs = DefineProperty<BinaryData>("Outputs", ["properties", "outputs"], isOutput: true);
        _provisioningState = DefineProperty<ResourcesProvisioningState>("ProvisioningState", ["properties", "provisioningState"], isOutput: true);
        _publisherTenantId = DefineProperty<Guid>("PublisherTenantId", ["properties", "publisherTenantId"], isOutput: true);
        _supportUris = DefineModelProperty<ArmApplicationPackageSupportUris>("SupportUris", ["properties", "supportUrls"], isOutput: true);
        _systemData = DefineModelProperty<SystemData>("SystemData", ["systemData"], isOutput: true);
        _updatedBy = DefineModelProperty<ArmApplicationDetails>("UpdatedBy", ["properties", "updatedBy"], isOutput: true);
    }

    /// <summary>
    /// Supported ArmApplication resource versions.
    /// </summary>
    public static class ResourceVersions
    {
        /// <summary>
        /// 2021-07-01.
        /// </summary>
        public static readonly string V2021_07_01 = "2021-07-01";

        /// <summary>
        /// 2019-07-01.
        /// </summary>
        public static readonly string V2019_07_01 = "2019-07-01";

        /// <summary>
        /// 2018-06-01.
        /// </summary>
        public static readonly string V2018_06_01 = "2018-06-01";

        /// <summary>
        /// 2018-03-01.
        /// </summary>
        public static readonly string V2018_03_01 = "2018-03-01";

        /// <summary>
        /// 2018-02-01.
        /// </summary>
        public static readonly string V2018_02_01 = "2018-02-01";

        /// <summary>
        /// 2017-12-01.
        /// </summary>
        public static readonly string V2017_12_01 = "2017-12-01";

        /// <summary>
        /// 2017-09-01.
        /// </summary>
        public static readonly string V2017_09_01 = "2017-09-01";
    }

    /// <summary>
    /// Creates a reference to an existing ArmApplication.
    /// </summary>
    /// <param name="bicepIdentifier">
    /// The the Bicep identifier name of the ArmApplication resource.  This can
    /// be used to refer to the resource in expressions, but is not the Azure
    /// name of the resource.  This value can contain letters, numbers, and
    /// underscores.
    /// </param>
    /// <param name="resourceVersion">Version of the ArmApplication.</param>
    /// <returns>The existing ArmApplication resource.</returns>
    public static ArmApplication FromExisting(string bicepIdentifier, string? resourceVersion = default) =>
        new(bicepIdentifier, resourceVersion) { IsExistingResource = true };
}

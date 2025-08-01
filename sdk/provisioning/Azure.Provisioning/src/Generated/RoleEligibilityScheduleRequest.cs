// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable enable

using Azure.Core;
using Azure.Provisioning.Primitives;
using Azure.Provisioning.Resources;
using System;

namespace Azure.Provisioning.Authorization;

/// <summary>
/// RoleEligibilityScheduleRequest.
/// </summary>
public partial class RoleEligibilityScheduleRequest : ProvisionableResource
{
    /// <summary>
    /// The name of the role eligibility to create. It can be any valid GUID.
    /// </summary>
    public BicepValue<string> Name 
    {
        get { Initialize(); return _name!; }
        set { Initialize(); _name!.Assign(value); }
    }
    private BicepValue<string>? _name;

    /// <summary>
    /// The conditions on the role assignment. This limits the resources it can
    /// be assigned to. e.g.:
    /// @Resource[Microsoft.Storage/storageAccounts/blobServices/containers:ContainerName]
    /// StringEqualsIgnoreCase &apos;foo_storage_container&apos;.
    /// </summary>
    public BicepValue<string> Condition 
    {
        get { Initialize(); return _condition!; }
        set { Initialize(); _condition!.Assign(value); }
    }
    private BicepValue<string>? _condition;

    /// <summary>
    /// Version of the condition. Currently accepted value is &apos;2.0&apos;.
    /// </summary>
    public BicepValue<string> ConditionVersion 
    {
        get { Initialize(); return _conditionVersion!; }
        set { Initialize(); _conditionVersion!.Assign(value); }
    }
    private BicepValue<string>? _conditionVersion;

    /// <summary>
    /// Duration of the role eligibility schedule in TimeSpan.
    /// </summary>
    public BicepValue<TimeSpan> Duration 
    {
        get { Initialize(); return _duration!; }
        set { Initialize(); _duration!.Assign(value); }
    }
    private BicepValue<TimeSpan>? _duration;

    /// <summary>
    /// End DateTime of the role eligibility schedule.
    /// </summary>
    public BicepValue<DateTimeOffset> EndOn 
    {
        get { Initialize(); return _endOn!; }
        set { Initialize(); _endOn!.Assign(value); }
    }
    private BicepValue<DateTimeOffset>? _endOn;

    /// <summary>
    /// Type of the role eligibility schedule expiration.
    /// </summary>
    public BicepValue<RoleManagementScheduleExpirationType> ExpirationType 
    {
        get { Initialize(); return _expirationType!; }
        set { Initialize(); _expirationType!.Assign(value); }
    }
    private BicepValue<RoleManagementScheduleExpirationType>? _expirationType;

    /// <summary>
    /// Justification for the role eligibility.
    /// </summary>
    public BicepValue<string> Justification 
    {
        get { Initialize(); return _justification!; }
        set { Initialize(); _justification!.Assign(value); }
    }
    private BicepValue<string>? _justification;

    /// <summary>
    /// The principal ID.
    /// </summary>
    public BicepValue<Guid> PrincipalId 
    {
        get { Initialize(); return _principalId!; }
        set { Initialize(); _principalId!.Assign(value); }
    }
    private BicepValue<Guid>? _principalId;

    /// <summary>
    /// The type of the role assignment schedule request. Eg: SelfActivate,
    /// AdminAssign etc.
    /// </summary>
    public BicepValue<RoleManagementScheduleRequestType> RequestType 
    {
        get { Initialize(); return _requestType!; }
        set { Initialize(); _requestType!.Assign(value); }
    }
    private BicepValue<RoleManagementScheduleRequestType>? _requestType;

    /// <summary>
    /// The role definition ID.
    /// </summary>
    public BicepValue<ResourceIdentifier> RoleDefinitionId 
    {
        get { Initialize(); return _roleDefinitionId!; }
        set { Initialize(); _roleDefinitionId!.Assign(value); }
    }
    private BicepValue<ResourceIdentifier>? _roleDefinitionId;

    /// <summary>
    /// Start DateTime of the role eligibility schedule.
    /// </summary>
    public BicepValue<DateTimeOffset> StartOn 
    {
        get { Initialize(); return _startOn!; }
        set { Initialize(); _startOn!.Assign(value); }
    }
    private BicepValue<DateTimeOffset>? _startOn;

    /// <summary>
    /// The resultant role eligibility schedule id or the role eligibility
    /// schedule id being updated.
    /// </summary>
    public BicepValue<ResourceIdentifier> TargetRoleEligibilityScheduleId 
    {
        get { Initialize(); return _targetRoleEligibilityScheduleId!; }
        set { Initialize(); _targetRoleEligibilityScheduleId!.Assign(value); }
    }
    private BicepValue<ResourceIdentifier>? _targetRoleEligibilityScheduleId;

    /// <summary>
    /// The role eligibility schedule instance id being updated.
    /// </summary>
    public BicepValue<ResourceIdentifier> TargetRoleEligibilityScheduleInstanceId 
    {
        get { Initialize(); return _targetRoleEligibilityScheduleInstanceId!; }
        set { Initialize(); _targetRoleEligibilityScheduleInstanceId!.Assign(value); }
    }
    private BicepValue<ResourceIdentifier>? _targetRoleEligibilityScheduleInstanceId;

    /// <summary>
    /// Ticket Info of the role eligibility.
    /// </summary>
    public RoleEligibilityScheduleRequestPropertiesTicketInfo TicketInfo 
    {
        get { Initialize(); return _ticketInfo!; }
        set { Initialize(); AssignOrReplace(ref _ticketInfo, value); }
    }
    private RoleEligibilityScheduleRequestPropertiesTicketInfo? _ticketInfo;

    /// <summary>
    /// The approvalId of the role eligibility schedule request.
    /// </summary>
    public BicepValue<string> ApprovalId 
    {
        get { Initialize(); return _approvalId!; }
    }
    private BicepValue<string>? _approvalId;

    /// <summary>
    /// DateTime when role eligibility schedule request was created.
    /// </summary>
    public BicepValue<DateTimeOffset> CreatedOn 
    {
        get { Initialize(); return _createdOn!; }
    }
    private BicepValue<DateTimeOffset>? _createdOn;

    /// <summary>
    /// Additional properties of principal, scope and role definition.
    /// </summary>
    public RoleManagementExpandedProperties ExpandedProperties 
    {
        get { Initialize(); return _expandedProperties!; }
    }
    private RoleManagementExpandedProperties? _expandedProperties;

    /// <summary>
    /// Gets the Id.
    /// </summary>
    public BicepValue<ResourceIdentifier> Id 
    {
        get { Initialize(); return _id!; }
    }
    private BicepValue<ResourceIdentifier>? _id;

    /// <summary>
    /// The principal type of the assigned principal ID.
    /// </summary>
    public BicepValue<RoleManagementPrincipalType> PrincipalType 
    {
        get { Initialize(); return _principalType!; }
    }
    private BicepValue<RoleManagementPrincipalType>? _principalType;

    /// <summary>
    /// Id of the user who created this request.
    /// </summary>
    public BicepValue<Guid> RequestorId 
    {
        get { Initialize(); return _requestorId!; }
    }
    private BicepValue<Guid>? _requestorId;

    /// <summary>
    /// The role eligibility schedule request scope.
    /// </summary>
    public BicepValue<string> Scope 
    {
        get { Initialize(); return _scope!; }
    }
    private BicepValue<string>? _scope;

    /// <summary>
    /// The status of the role eligibility schedule request.
    /// </summary>
    public BicepValue<RoleManagementScheduleStatus> Status 
    {
        get { Initialize(); return _status!; }
    }
    private BicepValue<RoleManagementScheduleStatus>? _status;

    /// <summary>
    /// Gets the SystemData.
    /// </summary>
    public SystemData SystemData 
    {
        get { Initialize(); return _systemData!; }
    }
    private SystemData? _systemData;

    /// <summary>
    /// Creates a new RoleEligibilityScheduleRequest.
    /// </summary>
    /// <param name="bicepIdentifier">
    /// The the Bicep identifier name of the RoleEligibilityScheduleRequest
    /// resource.  This can be used to refer to the resource in expressions,
    /// but is not the Azure name of the resource.  This value can contain
    /// letters, numbers, and underscores.
    /// </param>
    /// <param name="resourceVersion">Version of the RoleEligibilityScheduleRequest.</param>
    public RoleEligibilityScheduleRequest(string bicepIdentifier, string? resourceVersion = default)
        : base(bicepIdentifier, "Microsoft.Authorization/roleEligibilityScheduleRequests", resourceVersion ?? "2020-10-01")
    {
    }

    /// <summary>
    /// Define all the provisionable properties of
    /// RoleEligibilityScheduleRequest.
    /// </summary>
    protected override void DefineProvisionableProperties()
    {
        base.DefineProvisionableProperties();
        _name = DefineProperty<string>("Name", ["name"], isRequired: true);
        _condition = DefineProperty<string>("Condition", ["properties", "condition"]);
        _conditionVersion = DefineProperty<string>("ConditionVersion", ["properties", "conditionVersion"]);
        _duration = DefineProperty<TimeSpan>("Duration", ["properties", "duration"], format: "P");
        _endOn = DefineProperty<DateTimeOffset>("EndOn", ["properties", "endDateTime"]);
        _expirationType = DefineProperty<RoleManagementScheduleExpirationType>("ExpirationType", ["properties", "type"]);
        _justification = DefineProperty<string>("Justification", ["properties", "justification"]);
        _principalId = DefineProperty<Guid>("PrincipalId", ["properties", "principalId"]);
        _requestType = DefineProperty<RoleManagementScheduleRequestType>("RequestType", ["properties", "requestType"]);
        _roleDefinitionId = DefineProperty<ResourceIdentifier>("RoleDefinitionId", ["properties", "roleDefinitionId"]);
        _startOn = DefineProperty<DateTimeOffset>("StartOn", ["properties", "startDateTime"]);
        _targetRoleEligibilityScheduleId = DefineProperty<ResourceIdentifier>("TargetRoleEligibilityScheduleId", ["properties", "targetRoleEligibilityScheduleId"]);
        _targetRoleEligibilityScheduleInstanceId = DefineProperty<ResourceIdentifier>("TargetRoleEligibilityScheduleInstanceId", ["properties", "targetRoleEligibilityScheduleInstanceId"]);
        _ticketInfo = DefineModelProperty<RoleEligibilityScheduleRequestPropertiesTicketInfo>("TicketInfo", ["properties", "ticketInfo"]);
        _approvalId = DefineProperty<string>("ApprovalId", ["properties", "approvalId"], isOutput: true);
        _createdOn = DefineProperty<DateTimeOffset>("CreatedOn", ["properties", "createdOn"], isOutput: true);
        _expandedProperties = DefineModelProperty<RoleManagementExpandedProperties>("ExpandedProperties", ["properties", "expandedProperties"], isOutput: true);
        _id = DefineProperty<ResourceIdentifier>("Id", ["id"], isOutput: true);
        _principalType = DefineProperty<RoleManagementPrincipalType>("PrincipalType", ["properties", "principalType"], isOutput: true);
        _requestorId = DefineProperty<Guid>("RequestorId", ["properties", "requestorId"], isOutput: true);
        _scope = DefineProperty<string>("Scope", ["properties", "scope"], isOutput: true);
        _status = DefineProperty<RoleManagementScheduleStatus>("Status", ["properties", "status"], isOutput: true);
        _systemData = DefineModelProperty<SystemData>("SystemData", ["systemData"], isOutput: true);
    }

    /// <summary>
    /// Supported RoleEligibilityScheduleRequest resource versions.
    /// </summary>
    public static class ResourceVersions
    {
        /// <summary>
        /// 2020-10-01.
        /// </summary>
        public static readonly string V2020_10_01 = "2020-10-01";
    }

    /// <summary>
    /// Creates a reference to an existing RoleEligibilityScheduleRequest.
    /// </summary>
    /// <param name="bicepIdentifier">
    /// The the Bicep identifier name of the RoleEligibilityScheduleRequest
    /// resource.  This can be used to refer to the resource in expressions,
    /// but is not the Azure name of the resource.  This value can contain
    /// letters, numbers, and underscores.
    /// </param>
    /// <param name="resourceVersion">Version of the RoleEligibilityScheduleRequest.</param>
    /// <returns>The existing RoleEligibilityScheduleRequest resource.</returns>
    public static RoleEligibilityScheduleRequest FromExisting(string bicepIdentifier, string? resourceVersion = default) =>
        new(bicepIdentifier, resourceVersion) { IsExistingResource = true };
}

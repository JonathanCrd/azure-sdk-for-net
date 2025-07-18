// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure.Core;
using Azure.ResourceManager.Compute.Models;
using Azure.ResourceManager.Models;
using Azure.ResourceManager.Resources.Models;

namespace Azure.ResourceManager.Compute
{
    /// <summary>
    /// A class representing the ManagedDisk data model.
    /// Disk resource.
    /// </summary>
    public partial class ManagedDiskData : TrackedResourceData
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

        /// <summary> Initializes a new instance of <see cref="ManagedDiskData"/>. </summary>
        /// <param name="location"> The location. </param>
        public ManagedDiskData(AzureLocation location) : base(location)
        {
            ManagedByExtended = new ChangeTrackingList<ResourceIdentifier>();
            Zones = new ChangeTrackingList<string>();
            ShareInfo = new ChangeTrackingList<ShareInfoElement>();
        }

        /// <summary> Initializes a new instance of <see cref="ManagedDiskData"/>. </summary>
        /// <param name="id"> The id. </param>
        /// <param name="name"> The name. </param>
        /// <param name="resourceType"> The resourceType. </param>
        /// <param name="systemData"> The systemData. </param>
        /// <param name="tags"> The tags. </param>
        /// <param name="location"> The location. </param>
        /// <param name="managedBy"> A relative URI containing the ID of the VM that has the disk attached. </param>
        /// <param name="managedByExtended"> List of relative URIs containing the IDs of the VMs that have the disk attached. maxShares should be set to a value greater than one for disks to allow attaching them to multiple VMs. </param>
        /// <param name="sku"> The disks sku name. Can be Standard_LRS, Premium_LRS, StandardSSD_LRS, UltraSSD_LRS, Premium_ZRS, StandardSSD_ZRS, or PremiumV2_LRS. </param>
        /// <param name="zones"> The Logical zone list for Disk. </param>
        /// <param name="extendedLocation"> The extended location where the disk will be created. Extended location cannot be changed. </param>
        /// <param name="timeCreated"> The time when the disk was created. </param>
        /// <param name="osType"> The Operating System type. </param>
        /// <param name="hyperVGeneration"> The hypervisor generation of the Virtual Machine. Applicable to OS disks only. </param>
        /// <param name="purchasePlan"> Purchase plan information for the the image from which the OS disk was created. E.g. - {name: 2019-Datacenter, publisher: MicrosoftWindowsServer, product: WindowsServer}. </param>
        /// <param name="supportedCapabilities"> List of supported capabilities for the image from which the OS disk was created. </param>
        /// <param name="creationData"> Disk source information. CreationData information cannot be changed after the disk has been created. </param>
        /// <param name="diskSizeGB"> If creationData.createOption is Empty, this field is mandatory and it indicates the size of the disk to create. If this field is present for updates or creation with other options, it indicates a resize. Resizes are only allowed if the disk is not attached to a running VM, and can only increase the disk's size. </param>
        /// <param name="diskSizeBytes"> The size of the disk in bytes. This field is read only. </param>
        /// <param name="uniqueId"> Unique Guid identifying the resource. </param>
        /// <param name="encryptionSettingsGroup"> Encryption settings collection used for Azure Disk Encryption, can contain multiple encryption settings per disk or snapshot. </param>
        /// <param name="provisioningState"> The disk provisioning state. </param>
        /// <param name="diskIopsReadWrite"> The number of IOPS allowed for this disk; only settable for UltraSSD disks. One operation can transfer between 4k and 256k bytes. </param>
        /// <param name="diskMBpsReadWrite"> The bandwidth allowed for this disk; only settable for UltraSSD disks. MBps means millions of bytes per second - MB here uses the ISO notation, of powers of 10. </param>
        /// <param name="diskIopsReadOnly"> The total number of IOPS that will be allowed across all VMs mounting the shared disk as ReadOnly. One operation can transfer between 4k and 256k bytes. </param>
        /// <param name="diskMBpsReadOnly"> The total throughput (MBps) that will be allowed across all VMs mounting the shared disk as ReadOnly. MBps means millions of bytes per second - MB here uses the ISO notation, of powers of 10. </param>
        /// <param name="diskState"> The state of the disk. </param>
        /// <param name="encryption"> Encryption property can be used to encrypt data at rest with customer managed keys or platform managed keys. </param>
        /// <param name="maxShares"> The maximum number of VMs that can attach to the disk at the same time. Value greater than one indicates a disk that can be mounted on multiple VMs at the same time. </param>
        /// <param name="shareInfo"> Details of the list of all VMs that have the disk attached. maxShares should be set to a value greater than one for disks to allow attaching them to multiple VMs. </param>
        /// <param name="networkAccessPolicy"> Policy for accessing the disk via network. </param>
        /// <param name="diskAccessId"> ARM id of the DiskAccess resource for using private endpoints on disks. </param>
        /// <param name="burstingEnabledOn"> Latest time when bursting was last enabled on a disk. </param>
        /// <param name="tier"> Performance tier of the disk (e.g, P4, S10) as described here: https://azure.microsoft.com/en-us/pricing/details/managed-disks/. Does not apply to Ultra disks. </param>
        /// <param name="burstingEnabled"> Set to true to enable bursting beyond the provisioned performance target of the disk. Bursting is disabled by default. Does not apply to Ultra disks. </param>
        /// <param name="propertyUpdatesInProgress"> Properties of the disk for which update is pending. </param>
        /// <param name="supportsHibernation"> Indicates the OS on a disk supports hibernation. </param>
        /// <param name="securityProfile"> Contains the security related information for the resource. </param>
        /// <param name="completionPercent"> Percentage complete for the background copy when a resource is created via the CopyStart operation. </param>
        /// <param name="publicNetworkAccess"> Policy for controlling export on the disk. </param>
        /// <param name="dataAccessAuthMode"> Additional authentication requirements when exporting or uploading to a disk or snapshot. </param>
        /// <param name="isOptimizedForFrequentAttach"> Setting this property to true improves reliability and performance of data disks that are frequently (more than 5 times a day) by detached from one virtual machine and attached to another. This property should not be set for disks that are not detached and attached frequently as it causes the disks to not align with the fault domain of the virtual machine. </param>
        /// <param name="lastOwnershipUpdateOn"> The UTC time when the ownership state of the disk was last changed i.e., the time the disk was last attached or detached from a VM or the time when the VM to which the disk was attached was deallocated or started. </param>
        /// <param name="availabilityPolicy"> Determines how platform treats disk failures. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal ManagedDiskData(ResourceIdentifier id, string name, ResourceType resourceType, SystemData systemData, IDictionary<string, string> tags, AzureLocation location, ResourceIdentifier managedBy, IReadOnlyList<ResourceIdentifier> managedByExtended, DiskSku sku, IList<string> zones, ExtendedLocation extendedLocation, DateTimeOffset? timeCreated, SupportedOperatingSystemType? osType, HyperVGeneration? hyperVGeneration, DiskPurchasePlan purchasePlan, SupportedCapabilities supportedCapabilities, DiskCreationData creationData, int? diskSizeGB, long? diskSizeBytes, string uniqueId, EncryptionSettingsGroup encryptionSettingsGroup, string provisioningState, long? diskIopsReadWrite, long? diskMBpsReadWrite, long? diskIopsReadOnly, long? diskMBpsReadOnly, DiskState? diskState, DiskEncryption encryption, int? maxShares, IReadOnlyList<ShareInfoElement> shareInfo, NetworkAccessPolicy? networkAccessPolicy, ResourceIdentifier diskAccessId, DateTimeOffset? burstingEnabledOn, string tier, bool? burstingEnabled, PropertyUpdatesInProgress propertyUpdatesInProgress, bool? supportsHibernation, DiskSecurityProfile securityProfile, float? completionPercent, DiskPublicNetworkAccess? publicNetworkAccess, DataAccessAuthMode? dataAccessAuthMode, bool? isOptimizedForFrequentAttach, DateTimeOffset? lastOwnershipUpdateOn, AvailabilityPolicy availabilityPolicy, IDictionary<string, BinaryData> serializedAdditionalRawData) : base(id, name, resourceType, systemData, tags, location)
        {
            ManagedBy = managedBy;
            ManagedByExtended = managedByExtended;
            Sku = sku;
            Zones = zones;
            ExtendedLocation = extendedLocation;
            TimeCreated = timeCreated;
            OSType = osType;
            HyperVGeneration = hyperVGeneration;
            PurchasePlan = purchasePlan;
            SupportedCapabilities = supportedCapabilities;
            CreationData = creationData;
            DiskSizeGB = diskSizeGB;
            DiskSizeBytes = diskSizeBytes;
            UniqueId = uniqueId;
            EncryptionSettingsGroup = encryptionSettingsGroup;
            ProvisioningState = provisioningState;
            DiskIopsReadWrite = diskIopsReadWrite;
            DiskMBpsReadWrite = diskMBpsReadWrite;
            DiskIopsReadOnly = diskIopsReadOnly;
            DiskMBpsReadOnly = diskMBpsReadOnly;
            DiskState = diskState;
            Encryption = encryption;
            MaxShares = maxShares;
            ShareInfo = shareInfo;
            NetworkAccessPolicy = networkAccessPolicy;
            DiskAccessId = diskAccessId;
            BurstingEnabledOn = burstingEnabledOn;
            Tier = tier;
            BurstingEnabled = burstingEnabled;
            PropertyUpdatesInProgress = propertyUpdatesInProgress;
            SupportsHibernation = supportsHibernation;
            SecurityProfile = securityProfile;
            CompletionPercent = completionPercent;
            PublicNetworkAccess = publicNetworkAccess;
            DataAccessAuthMode = dataAccessAuthMode;
            IsOptimizedForFrequentAttach = isOptimizedForFrequentAttach;
            LastOwnershipUpdateOn = lastOwnershipUpdateOn;
            AvailabilityPolicy = availabilityPolicy;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Initializes a new instance of <see cref="ManagedDiskData"/> for deserialization. </summary>
        internal ManagedDiskData()
        {
        }

        /// <summary> A relative URI containing the ID of the VM that has the disk attached. </summary>
        public ResourceIdentifier ManagedBy { get; }
        /// <summary> List of relative URIs containing the IDs of the VMs that have the disk attached. maxShares should be set to a value greater than one for disks to allow attaching them to multiple VMs. </summary>
        public IReadOnlyList<ResourceIdentifier> ManagedByExtended { get; }
        /// <summary> The disks sku name. Can be Standard_LRS, Premium_LRS, StandardSSD_LRS, UltraSSD_LRS, Premium_ZRS, StandardSSD_ZRS, or PremiumV2_LRS. </summary>
        public DiskSku Sku { get; set; }
        /// <summary> The Logical zone list for Disk. </summary>
        public IList<string> Zones { get; }
        /// <summary> The extended location where the disk will be created. Extended location cannot be changed. </summary>
        public ExtendedLocation ExtendedLocation { get; set; }
        /// <summary> The time when the disk was created. </summary>
        public DateTimeOffset? TimeCreated { get; }
        /// <summary> The Operating System type. </summary>
        public SupportedOperatingSystemType? OSType { get; set; }
        /// <summary> The hypervisor generation of the Virtual Machine. Applicable to OS disks only. </summary>
        public HyperVGeneration? HyperVGeneration { get; set; }
        /// <summary> Purchase plan information for the the image from which the OS disk was created. E.g. - {name: 2019-Datacenter, publisher: MicrosoftWindowsServer, product: WindowsServer}. </summary>
        public DiskPurchasePlan PurchasePlan { get; set; }
        /// <summary> List of supported capabilities for the image from which the OS disk was created. </summary>
        public SupportedCapabilities SupportedCapabilities { get; set; }
        /// <summary> Disk source information. CreationData information cannot be changed after the disk has been created. </summary>
        public DiskCreationData CreationData { get; set; }
        /// <summary> If creationData.createOption is Empty, this field is mandatory and it indicates the size of the disk to create. If this field is present for updates or creation with other options, it indicates a resize. Resizes are only allowed if the disk is not attached to a running VM, and can only increase the disk's size. </summary>
        public int? DiskSizeGB { get; set; }
        /// <summary> The size of the disk in bytes. This field is read only. </summary>
        public long? DiskSizeBytes { get; }
        /// <summary> Unique Guid identifying the resource. </summary>
        public string UniqueId { get; }
        /// <summary> Encryption settings collection used for Azure Disk Encryption, can contain multiple encryption settings per disk or snapshot. </summary>
        public EncryptionSettingsGroup EncryptionSettingsGroup { get; set; }
        /// <summary> The disk provisioning state. </summary>
        public string ProvisioningState { get; }
        /// <summary> The number of IOPS allowed for this disk; only settable for UltraSSD disks. One operation can transfer between 4k and 256k bytes. </summary>
        public long? DiskIopsReadWrite { get; set; }
        /// <summary> The bandwidth allowed for this disk; only settable for UltraSSD disks. MBps means millions of bytes per second - MB here uses the ISO notation, of powers of 10. </summary>
        public long? DiskMBpsReadWrite { get; set; }
        /// <summary> The total number of IOPS that will be allowed across all VMs mounting the shared disk as ReadOnly. One operation can transfer between 4k and 256k bytes. </summary>
        public long? DiskIopsReadOnly { get; set; }
        /// <summary> The total throughput (MBps) that will be allowed across all VMs mounting the shared disk as ReadOnly. MBps means millions of bytes per second - MB here uses the ISO notation, of powers of 10. </summary>
        public long? DiskMBpsReadOnly { get; set; }
        /// <summary> The state of the disk. </summary>
        public DiskState? DiskState { get; }
        /// <summary> Encryption property can be used to encrypt data at rest with customer managed keys or platform managed keys. </summary>
        public DiskEncryption Encryption { get; set; }
        /// <summary> The maximum number of VMs that can attach to the disk at the same time. Value greater than one indicates a disk that can be mounted on multiple VMs at the same time. </summary>
        public int? MaxShares { get; set; }
        /// <summary> Details of the list of all VMs that have the disk attached. maxShares should be set to a value greater than one for disks to allow attaching them to multiple VMs. </summary>
        public IReadOnlyList<ShareInfoElement> ShareInfo { get; }
        /// <summary> Policy for accessing the disk via network. </summary>
        public NetworkAccessPolicy? NetworkAccessPolicy { get; set; }
        /// <summary> ARM id of the DiskAccess resource for using private endpoints on disks. </summary>
        public ResourceIdentifier DiskAccessId { get; set; }
        /// <summary> Latest time when bursting was last enabled on a disk. </summary>
        public DateTimeOffset? BurstingEnabledOn { get; }
        /// <summary> Performance tier of the disk (e.g, P4, S10) as described here: https://azure.microsoft.com/en-us/pricing/details/managed-disks/. Does not apply to Ultra disks. </summary>
        public string Tier { get; set; }
        /// <summary> Set to true to enable bursting beyond the provisioned performance target of the disk. Bursting is disabled by default. Does not apply to Ultra disks. </summary>
        public bool? BurstingEnabled { get; set; }
        /// <summary> Properties of the disk for which update is pending. </summary>
        internal PropertyUpdatesInProgress PropertyUpdatesInProgress { get; }
        /// <summary> The target performance tier of the disk if a tier change operation is in progress. </summary>
        public string PropertyUpdatesInProgressTargetTier
        {
            get => PropertyUpdatesInProgress?.TargetTier;
        }

        /// <summary> Indicates the OS on a disk supports hibernation. </summary>
        public bool? SupportsHibernation { get; set; }
        /// <summary> Contains the security related information for the resource. </summary>
        public DiskSecurityProfile SecurityProfile { get; set; }
        /// <summary> Percentage complete for the background copy when a resource is created via the CopyStart operation. </summary>
        public float? CompletionPercent { get; set; }
        /// <summary> Policy for controlling export on the disk. </summary>
        public DiskPublicNetworkAccess? PublicNetworkAccess { get; set; }
        /// <summary> Additional authentication requirements when exporting or uploading to a disk or snapshot. </summary>
        public DataAccessAuthMode? DataAccessAuthMode { get; set; }
        /// <summary> Setting this property to true improves reliability and performance of data disks that are frequently (more than 5 times a day) by detached from one virtual machine and attached to another. This property should not be set for disks that are not detached and attached frequently as it causes the disks to not align with the fault domain of the virtual machine. </summary>
        public bool? IsOptimizedForFrequentAttach { get; set; }
        /// <summary> The UTC time when the ownership state of the disk was last changed i.e., the time the disk was last attached or detached from a VM or the time when the VM to which the disk was attached was deallocated or started. </summary>
        public DateTimeOffset? LastOwnershipUpdateOn { get; }
        /// <summary> Determines how platform treats disk failures. </summary>
        internal AvailabilityPolicy AvailabilityPolicy { get; set; }
        /// <summary> Determines on how to handle disks with slow I/O. </summary>
        public AvailabilityPolicyDiskDelay? AvailabilityActionOnDiskDelay
        {
            get => AvailabilityPolicy is null ? default : AvailabilityPolicy.ActionOnDiskDelay;
            set
            {
                if (AvailabilityPolicy is null)
                    AvailabilityPolicy = new AvailabilityPolicy();
                AvailabilityPolicy.ActionOnDiskDelay = value;
            }
        }
    }
}

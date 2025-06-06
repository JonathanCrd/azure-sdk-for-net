// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text.Json;
using Azure.Core;

namespace Azure.ResourceManager.RecoveryServicesBackup.Models
{
    public partial class VmWorkloadSapHanaHsrProtectableItem : IUtf8JsonSerializable, IJsonModel<VmWorkloadSapHanaHsrProtectableItem>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<VmWorkloadSapHanaHsrProtectableItem>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<VmWorkloadSapHanaHsrProtectableItem>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VmWorkloadSapHanaHsrProtectableItem>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(VmWorkloadSapHanaHsrProtectableItem)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
        }

        VmWorkloadSapHanaHsrProtectableItem IJsonModel<VmWorkloadSapHanaHsrProtectableItem>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VmWorkloadSapHanaHsrProtectableItem>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(VmWorkloadSapHanaHsrProtectableItem)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeVmWorkloadSapHanaHsrProtectableItem(document.RootElement, options);
        }

        internal static VmWorkloadSapHanaHsrProtectableItem DeserializeVmWorkloadSapHanaHsrProtectableItem(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            string parentName = default;
            string parentUniqueName = default;
            string serverName = default;
            bool? isAutoProtectable = default;
            bool? isAutoProtected = default;
            int? subinquireditemcount = default;
            int? subprotectableitemcount = default;
            PreBackupValidation prebackupvalidation = default;
            bool? isProtectable = default;
            string backupManagementType = default;
            string workloadType = default;
            string protectableItemType = default;
            string friendlyName = default;
            BackupProtectionStatus? protectionState = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("parentName"u8))
                {
                    parentName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("parentUniqueName"u8))
                {
                    parentUniqueName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("serverName"u8))
                {
                    serverName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("isAutoProtectable"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    isAutoProtectable = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("isAutoProtected"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    isAutoProtected = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("subinquireditemcount"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    subinquireditemcount = property.Value.GetInt32();
                    continue;
                }
                if (property.NameEquals("subprotectableitemcount"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    subprotectableitemcount = property.Value.GetInt32();
                    continue;
                }
                if (property.NameEquals("prebackupvalidation"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    prebackupvalidation = PreBackupValidation.DeserializePreBackupValidation(property.Value, options);
                    continue;
                }
                if (property.NameEquals("isProtectable"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    isProtectable = property.Value.GetBoolean();
                    continue;
                }
                if (property.NameEquals("backupManagementType"u8))
                {
                    backupManagementType = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("workloadType"u8))
                {
                    workloadType = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("protectableItemType"u8))
                {
                    protectableItemType = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("friendlyName"u8))
                {
                    friendlyName = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("protectionState"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    protectionState = new BackupProtectionStatus(property.Value.GetString());
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new VmWorkloadSapHanaHsrProtectableItem(
                backupManagementType,
                workloadType,
                protectableItemType,
                friendlyName,
                protectionState,
                serializedAdditionalRawData,
                parentName,
                parentUniqueName,
                serverName,
                isAutoProtectable,
                isAutoProtected,
                subinquireditemcount,
                subprotectableitemcount,
                prebackupvalidation,
                isProtectable);
        }

        BinaryData IPersistableModel<VmWorkloadSapHanaHsrProtectableItem>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VmWorkloadSapHanaHsrProtectableItem>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerRecoveryServicesBackupContext.Default);
                default:
                    throw new FormatException($"The model {nameof(VmWorkloadSapHanaHsrProtectableItem)} does not support writing '{options.Format}' format.");
            }
        }

        VmWorkloadSapHanaHsrProtectableItem IPersistableModel<VmWorkloadSapHanaHsrProtectableItem>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<VmWorkloadSapHanaHsrProtectableItem>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeVmWorkloadSapHanaHsrProtectableItem(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(VmWorkloadSapHanaHsrProtectableItem)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<VmWorkloadSapHanaHsrProtectableItem>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}

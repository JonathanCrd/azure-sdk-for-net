// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.ResourceManager.Migration.Assessment.Models;
using Azure.ResourceManager.Models;

namespace Azure.ResourceManager.Migration.Assessment
{
    public partial class MigrationAssessmentGroupData : IUtf8JsonSerializable, IJsonModel<MigrationAssessmentGroupData>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<MigrationAssessmentGroupData>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<MigrationAssessmentGroupData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrationAssessmentGroupData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MigrationAssessmentGroupData)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (Optional.IsDefined(ProvisioningState))
            {
                writer.WritePropertyName("provisioningState"u8);
                writer.WriteStringValue(ProvisioningState.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(GroupStatus))
            {
                writer.WritePropertyName("groupStatus"u8);
                writer.WriteStringValue(GroupStatus.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(MachineCount))
            {
                writer.WritePropertyName("machineCount"u8);
                writer.WriteNumberValue(MachineCount.Value);
            }
            if (options.Format != "W" && Optional.IsCollectionDefined(Assessments))
            {
                writer.WritePropertyName("assessments"u8);
                writer.WriteStartArray();
                foreach (var item in Assessments)
                {
                    writer.WriteStringValue(item);
                }
                writer.WriteEndArray();
            }
            if (Optional.IsCollectionDefined(SupportedAssessmentTypes))
            {
                writer.WritePropertyName("supportedAssessmentTypes"u8);
                writer.WriteStartArray();
                foreach (var item in SupportedAssessmentTypes)
                {
                    writer.WriteStringValue(item.ToString());
                }
                writer.WriteEndArray();
            }
            if (options.Format != "W" && Optional.IsDefined(AreAssessmentsRunning))
            {
                writer.WritePropertyName("areAssessmentsRunning"u8);
                writer.WriteBooleanValue(AreAssessmentsRunning.Value);
            }
            if (options.Format != "W" && Optional.IsDefined(CreatedOn))
            {
                writer.WritePropertyName("createdTimestamp"u8);
                writer.WriteStringValue(CreatedOn.Value, "O");
            }
            if (options.Format != "W" && Optional.IsDefined(UpdatedOn))
            {
                writer.WritePropertyName("updatedTimestamp"u8);
                writer.WriteStringValue(UpdatedOn.Value, "O");
            }
            if (Optional.IsDefined(GroupType))
            {
                writer.WritePropertyName("groupType"u8);
                writer.WriteStringValue(GroupType.Value.ToString());
            }
            writer.WriteEndObject();
        }

        MigrationAssessmentGroupData IJsonModel<MigrationAssessmentGroupData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrationAssessmentGroupData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(MigrationAssessmentGroupData)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeMigrationAssessmentGroupData(document.RootElement, options);
        }

        internal static MigrationAssessmentGroupData DeserializeMigrationAssessmentGroupData(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            ResourceIdentifier id = default;
            string name = default;
            ResourceType type = default;
            SystemData systemData = default;
            MigrationAssessmentProvisioningState? provisioningState = default;
            MigrationAssessmentGroupStatus? groupStatus = default;
            int? machineCount = default;
            IReadOnlyList<string> assessments = default;
            IList<MigrationAssessmentType> supportedAssessmentTypes = default;
            bool? areAssessmentsRunning = default;
            DateTimeOffset? createdTimestamp = default;
            DateTimeOffset? updatedTimestamp = default;
            MigrationAssessmentGroupType? groupType = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("id"u8))
                {
                    id = new ResourceIdentifier(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("name"u8))
                {
                    name = property.Value.GetString();
                    continue;
                }
                if (property.NameEquals("type"u8))
                {
                    type = new ResourceType(property.Value.GetString());
                    continue;
                }
                if (property.NameEquals("systemData"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        continue;
                    }
                    systemData = ModelReaderWriter.Read<SystemData>(new BinaryData(Encoding.UTF8.GetBytes(property.Value.GetRawText())), ModelSerializationExtensions.WireOptions, AzureResourceManagerMigrationAssessmentContext.Default);
                    continue;
                }
                if (property.NameEquals("properties"u8))
                {
                    if (property.Value.ValueKind == JsonValueKind.Null)
                    {
                        property.ThrowNonNullablePropertyIsNull();
                        continue;
                    }
                    foreach (var property0 in property.Value.EnumerateObject())
                    {
                        if (property0.NameEquals("provisioningState"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            provisioningState = new MigrationAssessmentProvisioningState(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("groupStatus"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            groupStatus = new MigrationAssessmentGroupStatus(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("machineCount"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            machineCount = property0.Value.GetInt32();
                            continue;
                        }
                        if (property0.NameEquals("assessments"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            List<string> array = new List<string>();
                            foreach (var item in property0.Value.EnumerateArray())
                            {
                                array.Add(item.GetString());
                            }
                            assessments = array;
                            continue;
                        }
                        if (property0.NameEquals("supportedAssessmentTypes"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            List<MigrationAssessmentType> array = new List<MigrationAssessmentType>();
                            foreach (var item in property0.Value.EnumerateArray())
                            {
                                array.Add(new MigrationAssessmentType(item.GetString()));
                            }
                            supportedAssessmentTypes = array;
                            continue;
                        }
                        if (property0.NameEquals("areAssessmentsRunning"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            areAssessmentsRunning = property0.Value.GetBoolean();
                            continue;
                        }
                        if (property0.NameEquals("createdTimestamp"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            createdTimestamp = property0.Value.GetDateTimeOffset("O");
                            continue;
                        }
                        if (property0.NameEquals("updatedTimestamp"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            updatedTimestamp = property0.Value.GetDateTimeOffset("O");
                            continue;
                        }
                        if (property0.NameEquals("groupType"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            groupType = new MigrationAssessmentGroupType(property0.Value.GetString());
                            continue;
                        }
                    }
                    continue;
                }
                if (options.Format != "W")
                {
                    rawDataDictionary.Add(property.Name, BinaryData.FromString(property.Value.GetRawText()));
                }
            }
            serializedAdditionalRawData = rawDataDictionary;
            return new MigrationAssessmentGroupData(
                id,
                name,
                type,
                systemData,
                provisioningState,
                groupStatus,
                machineCount,
                assessments ?? new ChangeTrackingList<string>(),
                supportedAssessmentTypes ?? new ChangeTrackingList<MigrationAssessmentType>(),
                areAssessmentsRunning,
                createdTimestamp,
                updatedTimestamp,
                groupType,
                serializedAdditionalRawData);
        }

        BinaryData IPersistableModel<MigrationAssessmentGroupData>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrationAssessmentGroupData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerMigrationAssessmentContext.Default);
                default:
                    throw new FormatException($"The model {nameof(MigrationAssessmentGroupData)} does not support writing '{options.Format}' format.");
            }
        }

        MigrationAssessmentGroupData IPersistableModel<MigrationAssessmentGroupData>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<MigrationAssessmentGroupData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeMigrationAssessmentGroupData(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(MigrationAssessmentGroupData)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<MigrationAssessmentGroupData>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}

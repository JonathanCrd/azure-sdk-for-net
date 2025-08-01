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
using Azure.ResourceManager.Models;
using Azure.ResourceManager.Sql.Models;

namespace Azure.ResourceManager.Sql
{
    public partial class ManagedInstanceLongTermRetentionPolicyData : IUtf8JsonSerializable, IJsonModel<ManagedInstanceLongTermRetentionPolicyData>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<ManagedInstanceLongTermRetentionPolicyData>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<ManagedInstanceLongTermRetentionPolicyData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedInstanceLongTermRetentionPolicyData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ManagedInstanceLongTermRetentionPolicyData)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (Optional.IsDefined(BackupStorageAccessTier))
            {
                writer.WritePropertyName("backupStorageAccessTier"u8);
                writer.WriteStringValue(BackupStorageAccessTier.Value.ToString());
            }
            if (Optional.IsDefined(WeeklyRetention))
            {
                writer.WritePropertyName("weeklyRetention"u8);
                writer.WriteStringValue(WeeklyRetention);
            }
            if (Optional.IsDefined(MonthlyRetention))
            {
                writer.WritePropertyName("monthlyRetention"u8);
                writer.WriteStringValue(MonthlyRetention);
            }
            if (Optional.IsDefined(YearlyRetention))
            {
                writer.WritePropertyName("yearlyRetention"u8);
                writer.WriteStringValue(YearlyRetention);
            }
            if (Optional.IsDefined(WeekOfYear))
            {
                writer.WritePropertyName("weekOfYear"u8);
                writer.WriteNumberValue(WeekOfYear.Value);
            }
            writer.WriteEndObject();
        }

        ManagedInstanceLongTermRetentionPolicyData IJsonModel<ManagedInstanceLongTermRetentionPolicyData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedInstanceLongTermRetentionPolicyData>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ManagedInstanceLongTermRetentionPolicyData)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeManagedInstanceLongTermRetentionPolicyData(document.RootElement, options);
        }

        internal static ManagedInstanceLongTermRetentionPolicyData DeserializeManagedInstanceLongTermRetentionPolicyData(JsonElement element, ModelReaderWriterOptions options = null)
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
            SqlBackupStorageAccessTier? backupStorageAccessTier = default;
            string weeklyRetention = default;
            string monthlyRetention = default;
            string yearlyRetention = default;
            int? weekOfYear = default;
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
                    systemData = ModelReaderWriter.Read<SystemData>(new BinaryData(Encoding.UTF8.GetBytes(property.Value.GetRawText())), ModelSerializationExtensions.WireOptions, AzureResourceManagerSqlContext.Default);
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
                        if (property0.NameEquals("backupStorageAccessTier"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            backupStorageAccessTier = new SqlBackupStorageAccessTier(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("weeklyRetention"u8))
                        {
                            weeklyRetention = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("monthlyRetention"u8))
                        {
                            monthlyRetention = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("yearlyRetention"u8))
                        {
                            yearlyRetention = property0.Value.GetString();
                            continue;
                        }
                        if (property0.NameEquals("weekOfYear"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            weekOfYear = property0.Value.GetInt32();
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
            return new ManagedInstanceLongTermRetentionPolicyData(
                id,
                name,
                type,
                systemData,
                backupStorageAccessTier,
                weeklyRetention,
                monthlyRetention,
                yearlyRetention,
                weekOfYear,
                serializedAdditionalRawData);
        }

        private BinaryData SerializeBicep(ModelReaderWriterOptions options)
        {
            StringBuilder builder = new StringBuilder();
            BicepModelReaderWriterOptions bicepOptions = options as BicepModelReaderWriterOptions;
            IDictionary<string, string> propertyOverrides = null;
            bool hasObjectOverride = bicepOptions != null && bicepOptions.PropertyOverrides.TryGetValue(this, out propertyOverrides);
            bool hasPropertyOverride = false;
            string propertyOverride = null;

            builder.AppendLine("{");

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Name), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  name: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Name))
                {
                    builder.Append("  name: ");
                    if (Name.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{Name}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{Name}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(Id), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  id: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(Id))
                {
                    builder.Append("  id: ");
                    builder.AppendLine($"'{Id.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(SystemData), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("  systemData: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(SystemData))
                {
                    builder.Append("  systemData: ");
                    builder.AppendLine($"'{SystemData.ToString()}'");
                }
            }

            builder.Append("  properties:");
            builder.AppendLine(" {");
            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(BackupStorageAccessTier), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    backupStorageAccessTier: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(BackupStorageAccessTier))
                {
                    builder.Append("    backupStorageAccessTier: ");
                    builder.AppendLine($"'{BackupStorageAccessTier.Value.ToString()}'");
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(WeeklyRetention), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    weeklyRetention: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(WeeklyRetention))
                {
                    builder.Append("    weeklyRetention: ");
                    if (WeeklyRetention.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{WeeklyRetention}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{WeeklyRetention}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(MonthlyRetention), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    monthlyRetention: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(MonthlyRetention))
                {
                    builder.Append("    monthlyRetention: ");
                    if (MonthlyRetention.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{MonthlyRetention}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{MonthlyRetention}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(YearlyRetention), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    yearlyRetention: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(YearlyRetention))
                {
                    builder.Append("    yearlyRetention: ");
                    if (YearlyRetention.Contains(Environment.NewLine))
                    {
                        builder.AppendLine("'''");
                        builder.AppendLine($"{YearlyRetention}'''");
                    }
                    else
                    {
                        builder.AppendLine($"'{YearlyRetention}'");
                    }
                }
            }

            hasPropertyOverride = hasObjectOverride && propertyOverrides.TryGetValue(nameof(WeekOfYear), out propertyOverride);
            if (hasPropertyOverride)
            {
                builder.Append("    weekOfYear: ");
                builder.AppendLine(propertyOverride);
            }
            else
            {
                if (Optional.IsDefined(WeekOfYear))
                {
                    builder.Append("    weekOfYear: ");
                    builder.AppendLine($"{WeekOfYear.Value}");
                }
            }

            builder.AppendLine("  }");
            builder.AppendLine("}");
            return BinaryData.FromString(builder.ToString());
        }

        BinaryData IPersistableModel<ManagedInstanceLongTermRetentionPolicyData>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedInstanceLongTermRetentionPolicyData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerSqlContext.Default);
                case "bicep":
                    return SerializeBicep(options);
                default:
                    throw new FormatException($"The model {nameof(ManagedInstanceLongTermRetentionPolicyData)} does not support writing '{options.Format}' format.");
            }
        }

        ManagedInstanceLongTermRetentionPolicyData IPersistableModel<ManagedInstanceLongTermRetentionPolicyData>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ManagedInstanceLongTermRetentionPolicyData>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeManagedInstanceLongTermRetentionPolicyData(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(ManagedInstanceLongTermRetentionPolicyData)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<ManagedInstanceLongTermRetentionPolicyData>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}

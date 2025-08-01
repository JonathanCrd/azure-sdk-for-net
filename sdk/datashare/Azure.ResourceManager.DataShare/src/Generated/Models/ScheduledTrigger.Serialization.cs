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

namespace Azure.ResourceManager.DataShare.Models
{
    public partial class ScheduledTrigger : IUtf8JsonSerializable, IJsonModel<ScheduledTrigger>
    {
        void IUtf8JsonSerializable.Write(Utf8JsonWriter writer) => ((IJsonModel<ScheduledTrigger>)this).Write(writer, ModelSerializationExtensions.WireOptions);

        void IJsonModel<ScheduledTrigger>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            writer.WriteStartObject();
            JsonModelWriteCore(writer, options);
            writer.WriteEndObject();
        }

        /// <param name="writer"> The JSON writer. </param>
        /// <param name="options"> The client options for reading and writing models. </param>
        protected override void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ScheduledTrigger>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ScheduledTrigger)} does not support writing '{format}' format.");
            }

            base.JsonModelWriteCore(writer, options);
            writer.WritePropertyName("properties"u8);
            writer.WriteStartObject();
            if (options.Format != "W" && Optional.IsDefined(CreatedOn))
            {
                writer.WritePropertyName("createdAt"u8);
                writer.WriteStringValue(CreatedOn.Value, "O");
            }
            if (options.Format != "W" && Optional.IsDefined(ProvisioningState))
            {
                writer.WritePropertyName("provisioningState"u8);
                writer.WriteStringValue(ProvisioningState.Value.ToString());
            }
            writer.WritePropertyName("recurrenceInterval"u8);
            writer.WriteStringValue(RecurrenceInterval.ToString());
            if (Optional.IsDefined(SynchronizationMode))
            {
                writer.WritePropertyName("synchronizationMode"u8);
                writer.WriteStringValue(SynchronizationMode.Value.ToString());
            }
            writer.WritePropertyName("synchronizationTime"u8);
            writer.WriteStringValue(SynchronizeOn, "O");
            if (options.Format != "W" && Optional.IsDefined(TriggerStatus))
            {
                writer.WritePropertyName("triggerStatus"u8);
                writer.WriteStringValue(TriggerStatus.Value.ToString());
            }
            if (options.Format != "W" && Optional.IsDefined(UserName))
            {
                writer.WritePropertyName("userName"u8);
                writer.WriteStringValue(UserName);
            }
            writer.WriteEndObject();
        }

        ScheduledTrigger IJsonModel<ScheduledTrigger>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ScheduledTrigger>)this).GetFormatFromOptions(options) : options.Format;
            if (format != "J")
            {
                throw new FormatException($"The model {nameof(ScheduledTrigger)} does not support reading '{format}' format.");
            }

            using JsonDocument document = JsonDocument.ParseValue(ref reader);
            return DeserializeScheduledTrigger(document.RootElement, options);
        }

        internal static ScheduledTrigger DeserializeScheduledTrigger(JsonElement element, ModelReaderWriterOptions options = null)
        {
            options ??= ModelSerializationExtensions.WireOptions;

            if (element.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            TriggerKind kind = default;
            ResourceIdentifier id = default;
            string name = default;
            ResourceType type = default;
            SystemData systemData = default;
            DateTimeOffset? createdAt = default;
            DataShareProvisioningState? provisioningState = default;
            DataShareSynchronizationRecurrenceInterval recurrenceInterval = default;
            SynchronizationMode? synchronizationMode = default;
            DateTimeOffset synchronizationTime = default;
            DataShareTriggerStatus? triggerStatus = default;
            string userName = default;
            IDictionary<string, BinaryData> serializedAdditionalRawData = default;
            Dictionary<string, BinaryData> rawDataDictionary = new Dictionary<string, BinaryData>();
            foreach (var property in element.EnumerateObject())
            {
                if (property.NameEquals("kind"u8))
                {
                    kind = new TriggerKind(property.Value.GetString());
                    continue;
                }
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
                    systemData = ModelReaderWriter.Read<SystemData>(new BinaryData(Encoding.UTF8.GetBytes(property.Value.GetRawText())), ModelSerializationExtensions.WireOptions, AzureResourceManagerDataShareContext.Default);
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
                        if (property0.NameEquals("createdAt"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            createdAt = property0.Value.GetDateTimeOffset("O");
                            continue;
                        }
                        if (property0.NameEquals("provisioningState"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            provisioningState = new DataShareProvisioningState(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("recurrenceInterval"u8))
                        {
                            recurrenceInterval = new DataShareSynchronizationRecurrenceInterval(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("synchronizationMode"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            synchronizationMode = new SynchronizationMode(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("synchronizationTime"u8))
                        {
                            synchronizationTime = property0.Value.GetDateTimeOffset("O");
                            continue;
                        }
                        if (property0.NameEquals("triggerStatus"u8))
                        {
                            if (property0.Value.ValueKind == JsonValueKind.Null)
                            {
                                continue;
                            }
                            triggerStatus = new DataShareTriggerStatus(property0.Value.GetString());
                            continue;
                        }
                        if (property0.NameEquals("userName"u8))
                        {
                            userName = property0.Value.GetString();
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
            return new ScheduledTrigger(
                id,
                name,
                type,
                systemData,
                kind,
                serializedAdditionalRawData,
                createdAt,
                provisioningState,
                recurrenceInterval,
                synchronizationMode,
                synchronizationTime,
                triggerStatus,
                userName);
        }

        BinaryData IPersistableModel<ScheduledTrigger>.Write(ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ScheduledTrigger>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    return ModelReaderWriter.Write(this, options, AzureResourceManagerDataShareContext.Default);
                default:
                    throw new FormatException($"The model {nameof(ScheduledTrigger)} does not support writing '{options.Format}' format.");
            }
        }

        ScheduledTrigger IPersistableModel<ScheduledTrigger>.Create(BinaryData data, ModelReaderWriterOptions options)
        {
            var format = options.Format == "W" ? ((IPersistableModel<ScheduledTrigger>)this).GetFormatFromOptions(options) : options.Format;

            switch (format)
            {
                case "J":
                    {
                        using JsonDocument document = JsonDocument.Parse(data, ModelSerializationExtensions.JsonDocumentOptions);
                        return DeserializeScheduledTrigger(document.RootElement, options);
                    }
                default:
                    throw new FormatException($"The model {nameof(ScheduledTrigger)} does not support reading '{options.Format}' format.");
            }
        }

        string IPersistableModel<ScheduledTrigger>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}

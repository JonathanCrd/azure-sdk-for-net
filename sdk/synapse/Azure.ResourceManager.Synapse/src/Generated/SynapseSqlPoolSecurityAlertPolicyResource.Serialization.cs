// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;

namespace Azure.ResourceManager.Synapse
{
    public partial class SynapseSqlPoolSecurityAlertPolicyResource : IJsonModel<SynapseSqlPoolSecurityAlertPolicyData>
    {
        private static SynapseSqlPoolSecurityAlertPolicyData s_dataDeserializationInstance;
        private static SynapseSqlPoolSecurityAlertPolicyData DataDeserializationInstance => s_dataDeserializationInstance ??= new();

        void IJsonModel<SynapseSqlPoolSecurityAlertPolicyData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options) => ((IJsonModel<SynapseSqlPoolSecurityAlertPolicyData>)Data).Write(writer, options);

        SynapseSqlPoolSecurityAlertPolicyData IJsonModel<SynapseSqlPoolSecurityAlertPolicyData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => ((IJsonModel<SynapseSqlPoolSecurityAlertPolicyData>)DataDeserializationInstance).Create(ref reader, options);

        BinaryData IPersistableModel<SynapseSqlPoolSecurityAlertPolicyData>.Write(ModelReaderWriterOptions options) => ModelReaderWriter.Write<SynapseSqlPoolSecurityAlertPolicyData>(Data, options, AzureResourceManagerSynapseContext.Default);

        SynapseSqlPoolSecurityAlertPolicyData IPersistableModel<SynapseSqlPoolSecurityAlertPolicyData>.Create(BinaryData data, ModelReaderWriterOptions options) => ModelReaderWriter.Read<SynapseSqlPoolSecurityAlertPolicyData>(data, options, AzureResourceManagerSynapseContext.Default);

        string IPersistableModel<SynapseSqlPoolSecurityAlertPolicyData>.GetFormatFromOptions(ModelReaderWriterOptions options) => ((IPersistableModel<SynapseSqlPoolSecurityAlertPolicyData>)DataDeserializationInstance).GetFormatFromOptions(options);
    }
}

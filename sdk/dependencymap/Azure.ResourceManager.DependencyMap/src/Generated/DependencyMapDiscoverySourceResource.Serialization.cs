// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;

namespace Azure.ResourceManager.DependencyMap
{
    public partial class DependencyMapDiscoverySourceResource : IJsonModel<DependencyMapDiscoverySourceData>
    {
        private static DependencyMapDiscoverySourceData s_dataDeserializationInstance;
        private static DependencyMapDiscoverySourceData DataDeserializationInstance => s_dataDeserializationInstance ??= new();

        void IJsonModel<DependencyMapDiscoverySourceData>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options) => ((IJsonModel<DependencyMapDiscoverySourceData>)Data).Write(writer, options);

        DependencyMapDiscoverySourceData IJsonModel<DependencyMapDiscoverySourceData>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => ((IJsonModel<DependencyMapDiscoverySourceData>)DataDeserializationInstance).Create(ref reader, options);

        BinaryData IPersistableModel<DependencyMapDiscoverySourceData>.Write(ModelReaderWriterOptions options) => ModelReaderWriter.Write<DependencyMapDiscoverySourceData>(Data, options, AzureResourceManagerDependencyMapContext.Default);

        DependencyMapDiscoverySourceData IPersistableModel<DependencyMapDiscoverySourceData>.Create(BinaryData data, ModelReaderWriterOptions options) => ModelReaderWriter.Read<DependencyMapDiscoverySourceData>(data, options, AzureResourceManagerDependencyMapContext.Default);

        string IPersistableModel<DependencyMapDiscoverySourceData>.GetFormatFromOptions(ModelReaderWriterOptions options) => ((IPersistableModel<DependencyMapDiscoverySourceData>)DataDeserializationInstance).GetFormatFromOptions(options);
    }
}

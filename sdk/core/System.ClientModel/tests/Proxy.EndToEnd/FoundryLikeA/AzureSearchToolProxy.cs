// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ClientModel.Primitives;
using System.IO;
using System.Text.Json;
using OpenAILike.Responses;

namespace FoundryLikeA
{
    /// <summary>
    /// Proxy registered for <see cref="ResponseTool"/>, so it is considered for every <see cref="ResponseTool"/>
    /// subtype. It takes over reads only when the payload's "type" discriminator is "azure_search" and writes only
    /// <see cref="AzureSearchTool"/> instances; it declines everything else so the next proxy or the base library
    /// handles it.
    /// </summary>
    public sealed class AzureSearchToolProxy : ModelProxy<ResponseTool>, IJsonModel<ResponseTool>
    {
        private const string Discriminator = "azure_search";

        public override bool CanHandle(ResponseTool model, ModelReaderWriterOptions options) => model is AzureSearchTool;

        public override bool CanHandle(ReadOnlyMemory<byte> data, ModelReaderWriterOptions options)
        {
            using JsonDocument doc = JsonDocument.Parse(data);
            return HasDiscriminator(doc.RootElement);
        }

        public override bool CanHandle(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            Utf8JsonReader copy = reader;
            using JsonDocument doc = JsonDocument.ParseValue(ref copy);
            return HasDiscriminator(doc.RootElement);
        }

        private static bool HasDiscriminator(JsonElement element)
            => element.TryGetProperty("type", out var t) && t.GetString() == Discriminator;

        ResponseTool IJsonModel<ResponseTool>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options)
        {
            using JsonDocument doc = JsonDocument.ParseValue(ref reader);
            return AzureSearchTool.Deserialize(doc.RootElement);
        }

        // Pass-through: invoke the original model's writer directly rather than re-entering ModelReaderWriter.
        void IJsonModel<ResponseTool>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
            => ((IJsonModel<ResponseTool>)options.ProxiedModel!).Write(writer, options);

        public override ResponseTool Create(BinaryData data, ModelReaderWriterOptions options)
        {
            using JsonDocument doc = JsonDocument.Parse(data);
            return AzureSearchTool.Deserialize(doc.RootElement);
        }

        public override BinaryData Write(ModelReaderWriterOptions options)
        {
            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                ((IJsonModel<ResponseTool>)options.ProxiedModel!).Write(writer, options);
            }
            return BinaryData.FromBytes(stream.ToArray());
        }

        public override string GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
    }
}

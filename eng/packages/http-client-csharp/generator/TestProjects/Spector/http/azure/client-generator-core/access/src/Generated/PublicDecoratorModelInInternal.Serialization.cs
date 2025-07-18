// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.ClientModel.Primitives;
using System.Text.Json;
using Azure;

namespace _Specs_.Azure.ClientGenerator.Core.Access._InternalOperation
{
    public partial class PublicDecoratorModelInInternal : IJsonModel<PublicDecoratorModelInInternal>
    {
        internal PublicDecoratorModelInInternal() => throw null;

        void IJsonModel<PublicDecoratorModelInInternal>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options) => throw null;

        protected virtual void JsonModelWriteCore(Utf8JsonWriter writer, ModelReaderWriterOptions options) => throw null;

        PublicDecoratorModelInInternal IJsonModel<PublicDecoratorModelInInternal>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => throw null;

        protected virtual PublicDecoratorModelInInternal JsonModelCreateCore(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => throw null;

        BinaryData IPersistableModel<PublicDecoratorModelInInternal>.Write(ModelReaderWriterOptions options) => throw null;

        protected virtual BinaryData PersistableModelWriteCore(ModelReaderWriterOptions options) => throw null;

        PublicDecoratorModelInInternal IPersistableModel<PublicDecoratorModelInInternal>.Create(BinaryData data, ModelReaderWriterOptions options) => throw null;

        protected virtual PublicDecoratorModelInInternal PersistableModelCreateCore(BinaryData data, ModelReaderWriterOptions options) => throw null;

        string IPersistableModel<PublicDecoratorModelInInternal>.GetFormatFromOptions(ModelReaderWriterOptions options) => throw null;

        public static explicit operator PublicDecoratorModelInInternal(Response result) => throw null;
    }
}

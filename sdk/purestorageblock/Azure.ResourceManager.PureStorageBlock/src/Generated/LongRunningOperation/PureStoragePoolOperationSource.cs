// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.ClientModel.Primitives;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Azure.ResourceManager.PureStorageBlock
{
    internal class PureStoragePoolOperationSource : IOperationSource<PureStoragePoolResource>
    {
        private readonly ArmClient _client;

        internal PureStoragePoolOperationSource(ArmClient client)
        {
            _client = client;
        }

        PureStoragePoolResource IOperationSource<PureStoragePoolResource>.CreateResult(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<PureStoragePoolData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerPureStorageBlockContext.Default);
            return new PureStoragePoolResource(_client, data);
        }

        async ValueTask<PureStoragePoolResource> IOperationSource<PureStoragePoolResource>.CreateResultAsync(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<PureStoragePoolData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerPureStorageBlockContext.Default);
            return await Task.FromResult(new PureStoragePoolResource(_client, data)).ConfigureAwait(false);
        }
    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.ClientModel.Primitives;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Azure.ResourceManager.SpringAppDiscovery
{
    internal class SpringBootServerOperationSource : IOperationSource<SpringBootServerResource>
    {
        private readonly ArmClient _client;

        internal SpringBootServerOperationSource(ArmClient client)
        {
            _client = client;
        }

        SpringBootServerResource IOperationSource<SpringBootServerResource>.CreateResult(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SpringBootServerData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerSpringAppDiscoveryContext.Default);
            return new SpringBootServerResource(_client, data);
        }

        async ValueTask<SpringBootServerResource> IOperationSource<SpringBootServerResource>.CreateResultAsync(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SpringBootServerData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerSpringAppDiscoveryContext.Default);
            return await Task.FromResult(new SpringBootServerResource(_client, data)).ConfigureAwait(false);
        }
    }
}

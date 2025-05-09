// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.ClientModel.Primitives;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Azure.ResourceManager.RecoveryServicesSiteRecovery
{
    internal class SiteRecoveryNetworkMappingOperationSource : IOperationSource<SiteRecoveryNetworkMappingResource>
    {
        private readonly ArmClient _client;

        internal SiteRecoveryNetworkMappingOperationSource(ArmClient client)
        {
            _client = client;
        }

        SiteRecoveryNetworkMappingResource IOperationSource<SiteRecoveryNetworkMappingResource>.CreateResult(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SiteRecoveryNetworkMappingData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerRecoveryServicesSiteRecoveryContext.Default);
            return new SiteRecoveryNetworkMappingResource(_client, data);
        }

        async ValueTask<SiteRecoveryNetworkMappingResource> IOperationSource<SiteRecoveryNetworkMappingResource>.CreateResultAsync(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SiteRecoveryNetworkMappingData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerRecoveryServicesSiteRecoveryContext.Default);
            return await Task.FromResult(new SiteRecoveryNetworkMappingResource(_client, data)).ConfigureAwait(false);
        }
    }
}

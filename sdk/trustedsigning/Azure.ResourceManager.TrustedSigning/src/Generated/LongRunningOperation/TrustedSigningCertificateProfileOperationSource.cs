// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.ClientModel.Primitives;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Azure.ResourceManager.TrustedSigning
{
    internal class TrustedSigningCertificateProfileOperationSource : IOperationSource<TrustedSigningCertificateProfileResource>
    {
        private readonly ArmClient _client;

        internal TrustedSigningCertificateProfileOperationSource(ArmClient client)
        {
            _client = client;
        }

        TrustedSigningCertificateProfileResource IOperationSource<TrustedSigningCertificateProfileResource>.CreateResult(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<TrustedSigningCertificateProfileData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerTrustedSigningContext.Default);
            return new TrustedSigningCertificateProfileResource(_client, data);
        }

        async ValueTask<TrustedSigningCertificateProfileResource> IOperationSource<TrustedSigningCertificateProfileResource>.CreateResultAsync(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<TrustedSigningCertificateProfileData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerTrustedSigningContext.Default);
            return await Task.FromResult(new TrustedSigningCertificateProfileResource(_client, data)).ConfigureAwait(false);
        }
    }
}

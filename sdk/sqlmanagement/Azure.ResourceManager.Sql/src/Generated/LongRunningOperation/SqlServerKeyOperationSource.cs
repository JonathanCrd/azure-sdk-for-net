// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.ClientModel.Primitives;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;

namespace Azure.ResourceManager.Sql
{
    internal class SqlServerKeyOperationSource : IOperationSource<SqlServerKeyResource>
    {
        private readonly ArmClient _client;

        internal SqlServerKeyOperationSource(ArmClient client)
        {
            _client = client;
        }

        SqlServerKeyResource IOperationSource<SqlServerKeyResource>.CreateResult(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SqlServerKeyData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerSqlContext.Default);
            return new SqlServerKeyResource(_client, data);
        }

        async ValueTask<SqlServerKeyResource> IOperationSource<SqlServerKeyResource>.CreateResultAsync(Response response, CancellationToken cancellationToken)
        {
            var data = ModelReaderWriter.Read<SqlServerKeyData>(response.Content, ModelReaderWriterOptions.Json, AzureResourceManagerSqlContext.Default);
            return await Task.FromResult(new SqlServerKeyResource(_client, data)).ConfigureAwait(false);
        }
    }
}

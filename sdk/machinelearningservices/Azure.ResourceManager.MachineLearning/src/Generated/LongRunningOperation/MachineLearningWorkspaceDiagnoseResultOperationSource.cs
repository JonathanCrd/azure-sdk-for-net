// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.ResourceManager.MachineLearning.Models;

namespace Azure.ResourceManager.MachineLearning
{
    internal class MachineLearningWorkspaceDiagnoseResultOperationSource : IOperationSource<MachineLearningWorkspaceDiagnoseResult>
    {
        MachineLearningWorkspaceDiagnoseResult IOperationSource<MachineLearningWorkspaceDiagnoseResult>.CreateResult(Response response, CancellationToken cancellationToken)
        {
            using var document = JsonDocument.Parse(response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions);
            return MachineLearningWorkspaceDiagnoseResult.DeserializeMachineLearningWorkspaceDiagnoseResult(document.RootElement);
        }

        async ValueTask<MachineLearningWorkspaceDiagnoseResult> IOperationSource<MachineLearningWorkspaceDiagnoseResult>.CreateResultAsync(Response response, CancellationToken cancellationToken)
        {
            using var document = await JsonDocument.ParseAsync(response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions, cancellationToken).ConfigureAwait(false);
            return MachineLearningWorkspaceDiagnoseResult.DeserializeMachineLearningWorkspaceDiagnoseResult(document.RootElement);
        }
    }
}

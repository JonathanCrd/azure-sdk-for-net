// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager.Synapse.Models;

namespace Azure.ResourceManager.Synapse
{
    internal partial class IntegrationRuntimeAuthKeysRestOperations
    {
        private readonly TelemetryDetails _userAgent;
        private readonly HttpPipeline _pipeline;
        private readonly Uri _endpoint;
        private readonly string _apiVersion;

        /// <summary> Initializes a new instance of IntegrationRuntimeAuthKeysRestOperations. </summary>
        /// <param name="pipeline"> The HTTP pipeline for sending and receiving REST requests and responses. </param>
        /// <param name="applicationId"> The application id to use for user agent. </param>
        /// <param name="endpoint"> server parameter. </param>
        /// <param name="apiVersion"> Api Version. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="pipeline"/> or <paramref name="apiVersion"/> is null. </exception>
        public IntegrationRuntimeAuthKeysRestOperations(HttpPipeline pipeline, string applicationId, Uri endpoint = null, string apiVersion = default)
        {
            _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
            _endpoint = endpoint ?? new Uri("https://management.azure.com");
            _apiVersion = apiVersion ?? "2021-06-01-preview";
            _userAgent = new TelemetryDetails(GetType().Assembly, applicationId);
        }

        internal RequestUriBuilder CreateRegenerateRequestUri(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName, IntegrationRuntimeRegenerateKeyContent content)
        {
            var uri = new RawRequestUriBuilder();
            uri.Reset(_endpoint);
            uri.AppendPath("/subscriptions/", false);
            uri.AppendPath(subscriptionId, true);
            uri.AppendPath("/resourceGroups/", false);
            uri.AppendPath(resourceGroupName, true);
            uri.AppendPath("/providers/Microsoft.Synapse/workspaces/", false);
            uri.AppendPath(workspaceName, true);
            uri.AppendPath("/integrationRuntimes/", false);
            uri.AppendPath(integrationRuntimeName, true);
            uri.AppendPath("/regenerateAuthKey", false);
            uri.AppendQuery("api-version", _apiVersion, true);
            return uri;
        }

        internal HttpMessage CreateRegenerateRequest(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName, IntegrationRuntimeRegenerateKeyContent content)
        {
            var message = _pipeline.CreateMessage();
            var request = message.Request;
            request.Method = RequestMethod.Post;
            var uri = new RawRequestUriBuilder();
            uri.Reset(_endpoint);
            uri.AppendPath("/subscriptions/", false);
            uri.AppendPath(subscriptionId, true);
            uri.AppendPath("/resourceGroups/", false);
            uri.AppendPath(resourceGroupName, true);
            uri.AppendPath("/providers/Microsoft.Synapse/workspaces/", false);
            uri.AppendPath(workspaceName, true);
            uri.AppendPath("/integrationRuntimes/", false);
            uri.AppendPath(integrationRuntimeName, true);
            uri.AppendPath("/regenerateAuthKey", false);
            uri.AppendQuery("api-version", _apiVersion, true);
            request.Uri = uri;
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Content-Type", "application/json");
            var content0 = new Utf8JsonRequestContent();
            content0.JsonWriter.WriteObjectValue(content, ModelSerializationExtensions.WireOptions);
            request.Content = content0;
            _userAgent.Apply(message);
            return message;
        }

        /// <summary> Regenerate the authentication key for an integration runtime. </summary>
        /// <param name="subscriptionId"> The ID of the target subscription. </param>
        /// <param name="resourceGroupName"> The name of the resource group. The name is case insensitive. </param>
        /// <param name="workspaceName"> The name of the workspace. </param>
        /// <param name="integrationRuntimeName"> Integration runtime name. </param>
        /// <param name="content"> The parameters for regenerating integration runtime authentication key. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/>, <paramref name="integrationRuntimeName"/> or <paramref name="content"/> is null. </exception>
        /// <exception cref="ArgumentException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/> or <paramref name="integrationRuntimeName"/> is an empty string, and was expected to be non-empty. </exception>
        public async Task<Response<SynapseIntegrationRuntimeAuthKeys>> RegenerateAsync(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName, IntegrationRuntimeRegenerateKeyContent content, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(subscriptionId, nameof(subscriptionId));
            Argument.AssertNotNullOrEmpty(resourceGroupName, nameof(resourceGroupName));
            Argument.AssertNotNullOrEmpty(workspaceName, nameof(workspaceName));
            Argument.AssertNotNullOrEmpty(integrationRuntimeName, nameof(integrationRuntimeName));
            Argument.AssertNotNull(content, nameof(content));

            using var message = CreateRegenerateRequest(subscriptionId, resourceGroupName, workspaceName, integrationRuntimeName, content);
            await _pipeline.SendAsync(message, cancellationToken).ConfigureAwait(false);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        SynapseIntegrationRuntimeAuthKeys value = default;
                        using var document = await JsonDocument.ParseAsync(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions, cancellationToken).ConfigureAwait(false);
                        value = SynapseIntegrationRuntimeAuthKeys.DeserializeSynapseIntegrationRuntimeAuthKeys(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }

        /// <summary> Regenerate the authentication key for an integration runtime. </summary>
        /// <param name="subscriptionId"> The ID of the target subscription. </param>
        /// <param name="resourceGroupName"> The name of the resource group. The name is case insensitive. </param>
        /// <param name="workspaceName"> The name of the workspace. </param>
        /// <param name="integrationRuntimeName"> Integration runtime name. </param>
        /// <param name="content"> The parameters for regenerating integration runtime authentication key. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/>, <paramref name="integrationRuntimeName"/> or <paramref name="content"/> is null. </exception>
        /// <exception cref="ArgumentException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/> or <paramref name="integrationRuntimeName"/> is an empty string, and was expected to be non-empty. </exception>
        public Response<SynapseIntegrationRuntimeAuthKeys> Regenerate(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName, IntegrationRuntimeRegenerateKeyContent content, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(subscriptionId, nameof(subscriptionId));
            Argument.AssertNotNullOrEmpty(resourceGroupName, nameof(resourceGroupName));
            Argument.AssertNotNullOrEmpty(workspaceName, nameof(workspaceName));
            Argument.AssertNotNullOrEmpty(integrationRuntimeName, nameof(integrationRuntimeName));
            Argument.AssertNotNull(content, nameof(content));

            using var message = CreateRegenerateRequest(subscriptionId, resourceGroupName, workspaceName, integrationRuntimeName, content);
            _pipeline.Send(message, cancellationToken);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        SynapseIntegrationRuntimeAuthKeys value = default;
                        using var document = JsonDocument.Parse(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions);
                        value = SynapseIntegrationRuntimeAuthKeys.DeserializeSynapseIntegrationRuntimeAuthKeys(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }

        internal RequestUriBuilder CreateListRequestUri(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName)
        {
            var uri = new RawRequestUriBuilder();
            uri.Reset(_endpoint);
            uri.AppendPath("/subscriptions/", false);
            uri.AppendPath(subscriptionId, true);
            uri.AppendPath("/resourceGroups/", false);
            uri.AppendPath(resourceGroupName, true);
            uri.AppendPath("/providers/Microsoft.Synapse/workspaces/", false);
            uri.AppendPath(workspaceName, true);
            uri.AppendPath("/integrationRuntimes/", false);
            uri.AppendPath(integrationRuntimeName, true);
            uri.AppendPath("/listAuthKeys", false);
            uri.AppendQuery("api-version", _apiVersion, true);
            return uri;
        }

        internal HttpMessage CreateListRequest(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName)
        {
            var message = _pipeline.CreateMessage();
            var request = message.Request;
            request.Method = RequestMethod.Post;
            var uri = new RawRequestUriBuilder();
            uri.Reset(_endpoint);
            uri.AppendPath("/subscriptions/", false);
            uri.AppendPath(subscriptionId, true);
            uri.AppendPath("/resourceGroups/", false);
            uri.AppendPath(resourceGroupName, true);
            uri.AppendPath("/providers/Microsoft.Synapse/workspaces/", false);
            uri.AppendPath(workspaceName, true);
            uri.AppendPath("/integrationRuntimes/", false);
            uri.AppendPath(integrationRuntimeName, true);
            uri.AppendPath("/listAuthKeys", false);
            uri.AppendQuery("api-version", _apiVersion, true);
            request.Uri = uri;
            request.Headers.Add("Accept", "application/json");
            _userAgent.Apply(message);
            return message;
        }

        /// <summary> List authentication keys in an integration runtime. </summary>
        /// <param name="subscriptionId"> The ID of the target subscription. </param>
        /// <param name="resourceGroupName"> The name of the resource group. The name is case insensitive. </param>
        /// <param name="workspaceName"> The name of the workspace. </param>
        /// <param name="integrationRuntimeName"> Integration runtime name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/> or <paramref name="integrationRuntimeName"/> is null. </exception>
        /// <exception cref="ArgumentException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/> or <paramref name="integrationRuntimeName"/> is an empty string, and was expected to be non-empty. </exception>
        public async Task<Response<SynapseIntegrationRuntimeAuthKeys>> ListAsync(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(subscriptionId, nameof(subscriptionId));
            Argument.AssertNotNullOrEmpty(resourceGroupName, nameof(resourceGroupName));
            Argument.AssertNotNullOrEmpty(workspaceName, nameof(workspaceName));
            Argument.AssertNotNullOrEmpty(integrationRuntimeName, nameof(integrationRuntimeName));

            using var message = CreateListRequest(subscriptionId, resourceGroupName, workspaceName, integrationRuntimeName);
            await _pipeline.SendAsync(message, cancellationToken).ConfigureAwait(false);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        SynapseIntegrationRuntimeAuthKeys value = default;
                        using var document = await JsonDocument.ParseAsync(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions, cancellationToken).ConfigureAwait(false);
                        value = SynapseIntegrationRuntimeAuthKeys.DeserializeSynapseIntegrationRuntimeAuthKeys(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }

        /// <summary> List authentication keys in an integration runtime. </summary>
        /// <param name="subscriptionId"> The ID of the target subscription. </param>
        /// <param name="resourceGroupName"> The name of the resource group. The name is case insensitive. </param>
        /// <param name="workspaceName"> The name of the workspace. </param>
        /// <param name="integrationRuntimeName"> Integration runtime name. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/> or <paramref name="integrationRuntimeName"/> is null. </exception>
        /// <exception cref="ArgumentException"> <paramref name="subscriptionId"/>, <paramref name="resourceGroupName"/>, <paramref name="workspaceName"/> or <paramref name="integrationRuntimeName"/> is an empty string, and was expected to be non-empty. </exception>
        public Response<SynapseIntegrationRuntimeAuthKeys> List(string subscriptionId, string resourceGroupName, string workspaceName, string integrationRuntimeName, CancellationToken cancellationToken = default)
        {
            Argument.AssertNotNullOrEmpty(subscriptionId, nameof(subscriptionId));
            Argument.AssertNotNullOrEmpty(resourceGroupName, nameof(resourceGroupName));
            Argument.AssertNotNullOrEmpty(workspaceName, nameof(workspaceName));
            Argument.AssertNotNullOrEmpty(integrationRuntimeName, nameof(integrationRuntimeName));

            using var message = CreateListRequest(subscriptionId, resourceGroupName, workspaceName, integrationRuntimeName);
            _pipeline.Send(message, cancellationToken);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        SynapseIntegrationRuntimeAuthKeys value = default;
                        using var document = JsonDocument.Parse(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions);
                        value = SynapseIntegrationRuntimeAuthKeys.DeserializeSynapseIntegrationRuntimeAuthKeys(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }
    }
}

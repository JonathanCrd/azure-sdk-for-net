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

namespace Azure.AI.Language.QuestionAnswering
{
    internal partial class QuestionAnsweringRestClient
    {
        private readonly HttpPipeline _pipeline;
        private readonly Uri _endpoint;
        private readonly string _apiVersion;

        /// <summary> The ClientDiagnostics is used to provide tracing support for the client library. </summary>
        internal ClientDiagnostics ClientDiagnostics { get; }

        /// <summary> Initializes a new instance of QuestionAnsweringRestClient. </summary>
        /// <param name="clientDiagnostics"> The handler for diagnostic messaging in the client. </param>
        /// <param name="pipeline"> The HTTP pipeline for sending and receiving REST requests and responses. </param>
        /// <param name="endpoint"> Supported Cognitive Services endpoint (e.g., https://&lt;resource-name&gt;.api.cognitiveservices.azure.com). </param>
        /// <param name="apiVersion"> Api Version. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="clientDiagnostics"/>, <paramref name="pipeline"/>, <paramref name="endpoint"/> or <paramref name="apiVersion"/> is null. </exception>
        public QuestionAnsweringRestClient(ClientDiagnostics clientDiagnostics, HttpPipeline pipeline, Uri endpoint, string apiVersion = "2021-10-01")
        {
            ClientDiagnostics = clientDiagnostics ?? throw new ArgumentNullException(nameof(clientDiagnostics));
            _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
            _endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
            _apiVersion = apiVersion ?? throw new ArgumentNullException(nameof(apiVersion));
        }

        internal HttpMessage CreateGetAnswersRequest(string projectName, string deploymentName, AnswersOptions knowledgeBaseQueryOptions)
        {
            var message = _pipeline.CreateMessage();
            var request = message.Request;
            request.Method = RequestMethod.Post;
            var uri = new RawRequestUriBuilder();
            uri.Reset(_endpoint);
            uri.AppendRaw("/language", false);
            uri.AppendPath("/:query-knowledgebases", false);
            uri.AppendQuery("projectName", projectName, true);
            uri.AppendQuery("deploymentName", deploymentName, true);
            uri.AppendQuery("api-version", _apiVersion, true);
            request.Uri = uri;
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Content-Type", "application/json");
            var content = new Utf8JsonRequestContent();
            content.JsonWriter.WriteObjectValue(knowledgeBaseQueryOptions);
            request.Content = content;
            return message;
        }

        /// <summary> Answers the specified question using your knowledge base. </summary>
        /// <param name="projectName"> The name of the project to use. </param>
        /// <param name="deploymentName"> The name of the specific deployment of the project to use. </param>
        /// <param name="knowledgeBaseQueryOptions"> Post body of the request. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="projectName"/>, <paramref name="deploymentName"/> or <paramref name="knowledgeBaseQueryOptions"/> is null. </exception>
        public async Task<Response<AnswersResult>> GetAnswersAsync(string projectName, string deploymentName, AnswersOptions knowledgeBaseQueryOptions, CancellationToken cancellationToken = default)
        {
            if (projectName == null)
            {
                throw new ArgumentNullException(nameof(projectName));
            }
            if (deploymentName == null)
            {
                throw new ArgumentNullException(nameof(deploymentName));
            }
            if (knowledgeBaseQueryOptions == null)
            {
                throw new ArgumentNullException(nameof(knowledgeBaseQueryOptions));
            }

            using var message = CreateGetAnswersRequest(projectName, deploymentName, knowledgeBaseQueryOptions);
            await _pipeline.SendAsync(message, cancellationToken).ConfigureAwait(false);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        AnswersResult value = default;
                        using var document = await JsonDocument.ParseAsync(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions, cancellationToken).ConfigureAwait(false);
                        value = AnswersResult.DeserializeAnswersResult(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }

        /// <summary> Answers the specified question using your knowledge base. </summary>
        /// <param name="projectName"> The name of the project to use. </param>
        /// <param name="deploymentName"> The name of the specific deployment of the project to use. </param>
        /// <param name="knowledgeBaseQueryOptions"> Post body of the request. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="projectName"/>, <paramref name="deploymentName"/> or <paramref name="knowledgeBaseQueryOptions"/> is null. </exception>
        public Response<AnswersResult> GetAnswers(string projectName, string deploymentName, AnswersOptions knowledgeBaseQueryOptions, CancellationToken cancellationToken = default)
        {
            if (projectName == null)
            {
                throw new ArgumentNullException(nameof(projectName));
            }
            if (deploymentName == null)
            {
                throw new ArgumentNullException(nameof(deploymentName));
            }
            if (knowledgeBaseQueryOptions == null)
            {
                throw new ArgumentNullException(nameof(knowledgeBaseQueryOptions));
            }

            using var message = CreateGetAnswersRequest(projectName, deploymentName, knowledgeBaseQueryOptions);
            _pipeline.Send(message, cancellationToken);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        AnswersResult value = default;
                        using var document = JsonDocument.Parse(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions);
                        value = AnswersResult.DeserializeAnswersResult(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }

        internal HttpMessage CreateGetAnswersFromTextRequest(AnswersFromTextOptions textQueryOptions)
        {
            var message = _pipeline.CreateMessage();
            var request = message.Request;
            request.Method = RequestMethod.Post;
            var uri = new RawRequestUriBuilder();
            uri.Reset(_endpoint);
            uri.AppendRaw("/language", false);
            uri.AppendPath("/:query-text", false);
            uri.AppendQuery("api-version", _apiVersion, true);
            request.Uri = uri;
            request.Headers.Add("Accept", "application/json");
            request.Headers.Add("Content-Type", "application/json");
            var content = new Utf8JsonRequestContent();
            content.JsonWriter.WriteObjectValue(textQueryOptions);
            request.Content = content;
            return message;
        }

        /// <summary> Answers the specified question using the provided text in the body. </summary>
        /// <param name="textQueryOptions"> Post body of the request. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="textQueryOptions"/> is null. </exception>
        public async Task<Response<AnswersFromTextResult>> GetAnswersFromTextAsync(AnswersFromTextOptions textQueryOptions, CancellationToken cancellationToken = default)
        {
            if (textQueryOptions == null)
            {
                throw new ArgumentNullException(nameof(textQueryOptions));
            }

            using var message = CreateGetAnswersFromTextRequest(textQueryOptions);
            await _pipeline.SendAsync(message, cancellationToken).ConfigureAwait(false);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        AnswersFromTextResult value = default;
                        using var document = await JsonDocument.ParseAsync(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions, cancellationToken).ConfigureAwait(false);
                        value = AnswersFromTextResult.DeserializeAnswersFromTextResult(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }

        /// <summary> Answers the specified question using the provided text in the body. </summary>
        /// <param name="textQueryOptions"> Post body of the request. </param>
        /// <param name="cancellationToken"> The cancellation token to use. </param>
        /// <exception cref="ArgumentNullException"> <paramref name="textQueryOptions"/> is null. </exception>
        public Response<AnswersFromTextResult> GetAnswersFromText(AnswersFromTextOptions textQueryOptions, CancellationToken cancellationToken = default)
        {
            if (textQueryOptions == null)
            {
                throw new ArgumentNullException(nameof(textQueryOptions));
            }

            using var message = CreateGetAnswersFromTextRequest(textQueryOptions);
            _pipeline.Send(message, cancellationToken);
            switch (message.Response.Status)
            {
                case 200:
                    {
                        AnswersFromTextResult value = default;
                        using var document = JsonDocument.Parse(message.Response.ContentStream, ModelSerializationExtensions.JsonDocumentOptions);
                        value = AnswersFromTextResult.DeserializeAnswersFromTextResult(document.RootElement);
                        return Response.FromValue(value, message.Response);
                    }
                default:
                    throw new RequestFailedException(message.Response);
            }
        }
    }
}

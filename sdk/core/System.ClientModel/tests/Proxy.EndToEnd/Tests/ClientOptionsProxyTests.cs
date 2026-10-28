// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ClientModel;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FoundryLikeA;
using FoundryLikeB;
using NUnit.Framework;
using OpenAILike;
using OpenAILike.Mocks;
using OpenAILike.Responses;
using static Proxy.EndToEnd.Tests.ProxyTestPayloads;

namespace Proxy.EndToEnd.Tests
{
    /// <summary>
    /// The registration snapshot a mock client takes from its options at construction, the null checks of the libraries'
    /// provisional registration helpers, and concurrency isolation between requests and between clients. Registration
    /// lifecycle on <see cref="ClientPipelineOptions"/> itself is covered by System.ClientModel.Tests.
    /// </summary>
    public class ClientOptionsProxyTests
    {
        private static readonly ApiKeyCredential s_credential = new("local-test-key");

        [Test]
        public void RegistrationHelpers_RejectNullOptions()
        {
            Assert.Throws<ArgumentNullException>(() => FoundryLikeAExtensions.AddAzureSerializationExtensions((OpenAIClientOptions)null!));
            Assert.Throws<ArgumentNullException>(() => FoundryLikeAExtensions.AddAzureSerializationExtensions((ResponsesClientOptions)null!));
            Assert.Throws<ArgumentNullException>(() => FoundryLikeAExtensions.AddAzureSerializationExtensions((ModelReaderWriterOptions)null!));
            Assert.Throws<ArgumentNullException>(() => FoundryLikeBExtensions.AddBingSerializationExtensions((OpenAIClientOptions)null!));
            Assert.Throws<ArgumentNullException>(() => FoundryLikeBExtensions.AddBingSerializationExtensions((ResponsesClientOptions)null!));
            Assert.Throws<ArgumentNullException>(() => FoundryLikeBExtensions.AddBingSerializationExtensions((ModelReaderWriterOptions)null!));
        }

        [Test]
        public async Task ClientConstruction_FreezesProxyRegistrations()
        {
            var options = new ResponsesClientOptions
            {
                Transport = new CannedResponseTransport(ResponseJson("bing_grounding", "market", "en-US"))
            };
            options.AddAzureSerializationExtensions();
            var client = new ResponsesClient(s_credential, options);

            // Constructing the client creates its pipeline, which freezes the options and their registrations.
            Assert.Throws<InvalidOperationException>(
                () => options.ModelReaderWriterOptions!.AddProxy<ResponseTool>(new BingGroundingToolProxy()));
            Assert.Throws<InvalidOperationException>(
                () => options.AddBingSerializationExtensions());

            ResponseTool tool = (await client.GetResponseAsync("frozen")).Value.Tools.Single();
            Assert.That(tool, Is.InstanceOf<UnknownResponseTool>());
        }

        [Test]
        public async Task ClientConcurrentRequestsKeepSerializedToolsIndependent()
        {
            var transport = new CannedResponseTransport(ResponseJson("azure_search", "index_name", "response"));
            var options = new ResponsesClientOptions { Transport = transport };
            options.AddAzureSerializationExtensions();
            var client = new ResponsesClient(s_credential, options);
            var calls = new List<Task<ClientResult<ResponseResult>>>();

            for (int i = 0; i < 8; i++)
            {
                var request = new CreateResponseOptions("test-model", [ResponseItem.CreateUserMessageItem("hello")]);
                request.Tools.Add(new AzureSearchTool($"index-{i}"));
                calls.Add(Task.Run(() => client.CreateResponseAsync(request)));
            }

            ClientResult<ResponseResult>[] results = await Task.WhenAll(calls);

            var requestNames = new HashSet<string>();
            while (transport.RequestBodies.TryDequeue(out BinaryData? requestBody))
            {
                using JsonDocument document = JsonDocument.Parse(requestBody);
                requestNames.Add(document.RootElement.GetProperty("tools")[0].GetProperty("index_name").GetString()!);
            }

            Assert.That(requestNames, Has.Count.EqualTo(8));
            for (int i = 0; i < 8; i++)
            {
                Assert.That(requestNames, Does.Contain($"index-{i}"));
            }
            Assert.That(results.Select(r => r.Value.Tools.Single()), Is.All.InstanceOf<AzureSearchTool>());
        }

        [Test]
        public async Task SeparateClients_ConcurrentCallsDoNotShareProxyRegistrations()
        {
            using var barrier = new Barrier(2);
            var azureOptions = new ResponsesClientOptions
            {
                Transport = new CannedResponseTransport(ResponseJson("azure_search", "index_name", "docs"), processBarrier: barrier)
            };
            azureOptions.AddAzureSerializationExtensions();
            var bingOnlyOptions = new ResponsesClientOptions
            {
                Transport = new CannedResponseTransport(ResponseJson("azure_search", "index_name", "docs"), processBarrier: barrier)
            };
            bingOnlyOptions.AddBingSerializationExtensions();
            var azureClient = new ResponsesClient(s_credential, azureOptions);
            var bingOnlyClient = new ResponsesClient(s_credential, bingOnlyOptions);

            // Each call blocks inside the transport until both are in flight, so the reads genuinely overlap.
            Task<ClientResult<ResponseResult>> azureCall = Task.Factory.StartNew(
                () => azureClient.GetResponseAsync("azure"),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap();
            Task<ClientResult<ResponseResult>> bingOnlyCall = Task.Factory.StartNew(
                () => bingOnlyClient.GetResponseAsync("bing"),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default).Unwrap();
            await Task.WhenAll(azureCall, bingOnlyCall);

            Assert.That(azureCall.Result.Value.Tools.Single(), Is.InstanceOf<AzureSearchTool>());
            Assert.That(bingOnlyCall.Result.Value.Tools.Single(), Is.InstanceOf<UnknownResponseTool>());
        }
    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.ClientModel.Primitives;
using System.Collections.Generic;
using FoundryLikeA;
using FoundryLikeB;
using NUnit.Framework;
using OpenAILike.Responses;

namespace Proxy.EndToEnd.Tests
{
    /// <summary>
    /// The end user's view of the proxy feature with direct <see cref="ModelReaderWriter"/> reads. They reference two
    /// independent libraries (FoundryLikeA = azure_search, FoundryLikeB = bing_grounding) that do not know about each
    /// other. The end user's job is one registration call per library, after which reading an OpenAILike
    /// <see cref="ResponseTool"/> returns the right strongly typed subtype. The registration helper names are
    /// provisional.
    /// </summary>
    public class EndUserProxyTests
    {
        // Everything the end user writes: opt into the libraries' tools once, then read tools normally.
        private static ResponseTool ReadTool(string json, Action<ModelReaderWriterOptions>? useLibraries = null)
        {
            var options = new ModelReaderWriterOptions("J");
            useLibraries?.Invoke(options);
            return ModelReaderWriter.Read<ResponseTool>(BinaryData.FromString(json), options)!;
        }

        private static void UseBothLibraries(ModelReaderWriterOptions options)
        {
            options.AddAzureSerializationExtensions();
            options.AddBingSerializationExtensions();
        }

        [Test]
        public void EndUser_GetsAzureStrongType_Transparently()
        {
            ResponseTool tool = ReadTool(ProxyTestPayloads.AzureToolJson, UseBothLibraries);

            Assert.That(tool, Is.InstanceOf<AzureSearchTool>());
            Assert.That(tool.GetType().Assembly, Is.EqualTo(typeof(AzureSearchTool).Assembly));
            Assert.That(((AzureSearchTool)tool).IndexName, Is.EqualTo("docs"));
        }

        [Test]
        public void EndUser_GetsBingStrongType_Transparently()
        {
            ResponseTool tool = ReadTool(ProxyTestPayloads.BingToolJson, UseBothLibraries);

            Assert.That(tool, Is.InstanceOf<BingGroundingTool>());
            Assert.That(tool.GetType().Assembly, Is.EqualTo(typeof(BingGroundingTool).Assembly));
            Assert.That(((BingGroundingTool)tool).Market, Is.EqualTo("en-US"));
        }

        [Test]
        public void BothLibraries_UnknownDiscriminator_FallsBackToOpenAI()
        {
            // A discriminator neither library claims -> the base library's own Unknown fallback.
            ResponseTool tool = ReadTool("{\"type\":\"totally_unknown\"}", UseBothLibraries);

            Assert.That(tool, Is.Not.InstanceOf<AzureSearchTool>());
            Assert.That(tool, Is.Not.InstanceOf<BingGroundingTool>());
            Assert.That(tool, Is.InstanceOf<UnknownResponseTool>());
            Assert.That(tool.GetType().Assembly, Is.EqualTo(typeof(ResponseTool).Assembly));
        }

        [Test]
        public void OnlyAzureLibraryUsed_BingDiscriminator_FallsBack()
        {
            // Independence: without FoundryLikeB enabled, its discriminator stays with the base library.
            ResponseTool tool = ReadTool(ProxyTestPayloads.BingToolJson, o => o.AddAzureSerializationExtensions());

            Assert.That(tool, Is.Not.InstanceOf<BingGroundingTool>());
            Assert.That(tool.GetType().Assembly, Is.EqualTo(typeof(ResponseTool).Assembly));
        }

        [Test]
        public void NoLibrariesUsed_AzureDiscriminator_FallsBack()
        {
            // Baseline: enable nothing -> the base library never produces a Foundry-like type.
            ResponseTool tool = ReadTool(ProxyTestPayloads.AzureToolJson);

            Assert.That(tool, Is.Not.InstanceOf<AzureSearchTool>());
            Assert.That(tool.GetType().Assembly, Is.EqualTo(typeof(ResponseTool).Assembly));
        }

        [Test]
        public void ResponseToolProxy_AppliesToAzureSearchTool_OnWriteAndRead()
        {
            var proxy = new RecordingResponseToolProxy(new AzureSearchToolProxy());
            var options = new ModelReaderWriterOptions("J");
            options.Proxies.Add(proxy);
            var tool = new AzureSearchTool("docs");

            // The proxy is registered for ResponseTool, and matching uses the model's runtime type, so the same
            // instance goes through the proxy whether it is written as ResponseTool or as AzureSearchTool.
            byte[] asBase = ModelReaderWriter.Write<ResponseTool>(tool, options).ToArray();
            Assert.That(proxy.Writes, Is.EqualTo(1));
            byte[] asDerived = ModelReaderWriter.Write(tool, options).ToArray();
            Assert.That(proxy.Writes, Is.EqualTo(2));
            byte[] asObject = ModelReaderWriter.Write<object>(tool, options).ToArray();
            Assert.That(proxy.Writes, Is.EqualTo(3));

            Assert.That(asDerived, Is.EqualTo(asBase));
            Assert.That(asObject, Is.EqualTo(asBase));
            Assert.That(BinaryData.FromBytes(asBase).ToString(), Is.EqualTo(ProxyTestPayloads.AzureToolJson));

            ResponseTool read = ModelReaderWriter.Read<ResponseTool>(BinaryData.FromBytes(asDerived), options)!;
            Assert.That(proxy.Reads, Is.EqualTo(1));
            Assert.That(read, Is.InstanceOf<AzureSearchTool>());
            Assert.That(((AzureSearchTool)read).IndexName, Is.EqualTo("docs"));
        }

        [Test]
        public void LibraryHelper_WritesAzureSearchToolIdenticallyThroughBaseAndDerivedTypes()
        {
            var options = new ModelReaderWriterOptions("J");
            UseBothLibraries(options);
            var tool = new AzureSearchTool("docs");

            BinaryData asBase = ModelReaderWriter.Write<ResponseTool>(tool, options);
            BinaryData asDerived = ModelReaderWriter.Write(tool, options);

            Assert.That(asDerived.ToArray(), Is.EqualTo(asBase.ToArray()));
            Assert.That(asBase.ToString(), Is.EqualTo(ProxyTestPayloads.AzureToolJson));
            Assert.That(ModelReaderWriter.Read<ResponseTool>(asDerived, options), Is.InstanceOf<AzureSearchTool>());
        }

        [Test]
        public void AzureSearchToolProxy_DoesNotHandleSiblingBingTool()
        {
            var proxy = new RecordingResponseToolProxy(new AzureSearchToolProxy());
            var options = new ModelReaderWriterOptions("J");
            options.Proxies.Add(proxy);
            var bing = new BingGroundingTool("en-US");

            Assert.That(new AzureSearchToolProxy().CanHandle(bing, options), Is.False);
            Assert.That(new AzureSearchToolProxy().CanHandle(BinaryData.FromString(ProxyTestPayloads.BingToolJson).ToMemory(), options), Is.False);

            byte[] expected = ModelReaderWriter.Write<ResponseTool>(bing, ModelReaderWriterOptions.Json).ToArray();
            Assert.That(ModelReaderWriter.Write<ResponseTool>(bing, options).ToArray(), Is.EqualTo(expected));
            Assert.That(ModelReaderWriter.Write(bing, options).ToArray(), Is.EqualTo(expected));
            Assert.That(proxy.Writes, Is.Zero);

            ResponseTool read = ModelReaderWriter.Read<ResponseTool>(BinaryData.FromString(ProxyTestPayloads.BingToolJson), options)!;
            Assert.That(proxy.Reads, Is.Zero);
            Assert.That(read, Is.InstanceOf<UnknownResponseTool>());
        }

        [Test]
        public void BothLibraries_RouteMixedAndNestedCollections()
        {
            string payload = $"[{ProxyTestPayloads.AzureToolJson},{ProxyTestPayloads.BingToolJson},"
                + "{\"type\":\"function\",\"function_name\":\"get_weather\"},{\"type\":\"unrecognized\"}]";
            var options = new ModelReaderWriterOptions("J");
            UseBothLibraries(options);

            List<ResponseTool>? tools = ModelReaderWriter.Read<List<ResponseTool>>(BinaryData.FromString(payload), options);
            List<List<ResponseTool>>? nested = ModelReaderWriter.Read<List<List<ResponseTool>>>(
                BinaryData.FromString($"[{payload}]"), options);

            Assert.That(tools, Is.Not.Null);
            Assert.That(nested, Is.Not.Null);
            Assert.That(nested!, Has.Count.EqualTo(1));
            AssertMixedTools(tools!);
            AssertMixedTools(nested![0]);
        }

        private static void AssertMixedTools(IReadOnlyList<ResponseTool> tools)
        {
            Assert.That(tools, Has.Count.EqualTo(4));
            Assert.That(tools[0], Is.InstanceOf<AzureSearchTool>());
            Assert.That(tools[0].GetType().Assembly, Is.EqualTo(typeof(AzureSearchTool).Assembly));
            Assert.That(((AzureSearchTool)tools[0]).IndexName, Is.EqualTo("docs"));
            Assert.That(tools[1], Is.InstanceOf<BingGroundingTool>());
            Assert.That(tools[1].GetType().Assembly, Is.EqualTo(typeof(BingGroundingTool).Assembly));
            Assert.That(((BingGroundingTool)tools[1]).Market, Is.EqualTo("en-US"));
            Assert.That(tools[2], Is.InstanceOf<FunctionTool>());
            Assert.That(tools[2].GetType().Assembly, Is.EqualTo(typeof(ResponseTool).Assembly));
            Assert.That(tools[3], Is.InstanceOf<UnknownResponseTool>());
            Assert.That(tools[3].GetType().Assembly, Is.EqualTo(typeof(ResponseTool).Assembly));
        }
    }
}

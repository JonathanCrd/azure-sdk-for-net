// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.ClientModel.Primitives;
using System.ClientModel.Tests.Proxy.FirstPartyA;
using System.ClientModel.Tests.Proxy.OpenAILike;
using System.ClientModel.Tests.Proxy.OpenAILike.Mocks;
using System.ClientModel.Tests.Proxy.ThirdPartyB;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace System.ClientModel.Tests.ModelReaderWriterTests
{
    /// <summary>
    /// A <b>truly end-to-end</b> demonstration of the OpenAI -> Foundry conditional-deserialization
    /// scenario. Unlike a bare <see cref="ModelReaderWriter"/> call, each test drives a real
    /// <see cref="ResponseToolsClient"/> whose <see cref="ClientPipeline"/> uses a mock transport that
    /// returns a canned response body — i.e. we register the proxy, mock the response, run a client
    /// call, and verify the expected derived type comes back. Asserting the concrete runtime type AND
    /// the owning assembly proves the deserialization physically ran in the third-party DLL, not the base.
    /// </summary>
    public class ProxyEndToEndTests
    {
        // Builds a client whose transport returns the given canned response body, with optional proxies registered.
        private static ResponseToolsClient CreateClient(string cannedResponseJson, Action<ClientPipelineOptions>? registerProxies = null)
        {
            var pipelineOptions = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport(cannedResponseJson)
            };
            registerProxies?.Invoke(pipelineOptions);

            return new ResponseToolsClient(pipelineOptions);
        }

        private static void RegisterBothProxies(ClientPipelineOptions options)
        {
            options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
            options.AddProxy<ResponseTool>(new BingGroundingToolProxy());
        }

        [Test]
        public void FunctionTool_HandledByBase()
        {
            ResponseToolsClient client = CreateClient("{\"type\":\"function\",\"function_name\":\"get_weather\"}", RegisterBothProxies);

            ResponseTool tool = client.GetTool("t1");

            Assert.IsInstanceOf<FunctionTool>(tool);
            Assert.AreEqual(typeof(ResponseTool).Assembly, tool.GetType().Assembly);
            Assert.AreEqual("get_weather", ((FunctionTool)tool).FunctionName);
        }

        [Test]
        public void AzureSearch_RoutedToFirstPartyA()
        {
            ResponseToolsClient client = CreateClient("{\"type\":\"azure_search\",\"index_name\":\"docs\"}", RegisterBothProxies);

            ResponseTool tool = client.GetTool("t2");

            Assert.IsInstanceOf<AzureSearchTool>(tool);
            Assert.AreEqual(typeof(AzureSearchTool).Assembly, tool.GetType().Assembly);
            Assert.AreEqual("docs", ((AzureSearchTool)tool).IndexName);
        }

        [Test]
        public void DirectClient_RegistersAzureProxyOnClientOptions()
        {
            ResponseToolsClient client = CreateClient(
                "{\"type\":\"azure_search\",\"index_name\":\"docs\"}",
                options => options.AddProxy<ResponseTool>(new AzureSearchToolProxy()));

            Assert.IsInstanceOf<AzureSearchTool>(client.GetTool("direct"));
        }

        [Test]
        public void DirectClient_SerializesRequestAndDeserializesProxiedResponse()
        {
            var transport = new CannedResponseTransport("{\"type\":\"azure_search\",\"index_name\":\"response-docs\"}");
            var options = new ClientPipelineOptions { Transport = transport };
            options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
            var client = new ResponseToolsClient(options);

            ResponseTool response = client.SubmitTool(new AzureSearchTool("request-docs"));

            Assert.IsTrue(transport.RequestBodies.TryDequeue(out BinaryData? requestBody));
            Assert.AreEqual("{\"type\":\"azure_search\",\"index_name\":\"request-docs\"}", requestBody!.ToString());
            Assert.IsInstanceOf<AzureSearchTool>(response);
            Assert.AreEqual("response-docs", ((AzureSearchTool)response).IndexName);
            Assert.AreEqual(typeof(AzureSearchTool).Assembly, response.GetType().Assembly);
        }

        [Test]
        public void DirectClient_ConcurrentRequestsKeepSerializedToolsIndependent()
        {
            var transport = new CannedResponseTransport("{\"type\":\"azure_search\",\"index_name\":\"response\"}");
            var options = new ClientPipelineOptions { Transport = transport };
            options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
            var client = new ResponseToolsClient(options);
            var calls = new List<Task<ResponseTool>>();

            for (int i = 0; i < 8; i++)
            {
                int index = i;
                calls.Add(Task.Run(() => client.SubmitTool(new AzureSearchTool($"index-{index}"))));
            }

            Task.WaitAll(calls.ToArray());

            var requestNames = new HashSet<string>();
            while (transport.RequestBodies.TryDequeue(out BinaryData? requestBody))
            {
                using JsonDocument document = JsonDocument.Parse(requestBody.ToString());
                requestNames.Add(document.RootElement.GetProperty("index_name").GetString()!);
            }

            Assert.AreEqual(8, requestNames.Count);
            for (int i = 0; i < 8; i++)
            {
                Assert.IsTrue(requestNames.Contains($"index-{i}"));
                Assert.IsInstanceOf<AzureSearchTool>(calls[i].Result);
            }
        }

        [Test]
        public void Subclient_InheritsProxyRegistrationsAndUsesItsOwnRequestPath()
        {
            var transport = new CannedResponseTransport("{\"type\":\"azure_search\",\"index_name\":\"docs\"}");
            var options = new ClientPipelineOptions { Transport = transport };
            options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
            var subclient = new ResponseToolsClient(options).GetSubclient("group");

            ResponseTool result = subclient.GetTool("tool");

            Assert.IsInstanceOf<AzureSearchTool>(result);
            Assert.IsTrue(transport.RequestUris.TryDequeue(out Uri? requestUri));
            Assert.AreEqual("/subclients/group/tools/tool", requestUri!.AbsolutePath);
        }

        [Test]
        public void BingGrounding_RoutedToThirdPartyB()
        {
            ResponseToolsClient client = CreateClient("{\"type\":\"bing_grounding\",\"market\":\"en-US\"}", RegisterBothProxies);

            ResponseTool tool = client.GetTool("t3");

            Assert.IsInstanceOf<BingGroundingTool>(tool);
            Assert.AreEqual(typeof(BingGroundingTool).Assembly, tool.GetType().Assembly);
            Assert.AreEqual("en-US", ((BingGroundingTool)tool).Market);
        }

        [Test]
        public void UnknownDiscriminator_FallsBackToBase()
        {
            ResponseToolsClient client = CreateClient("{\"type\":\"web_search\"}", RegisterBothProxies);

            ResponseTool tool = client.GetTool("t4");

            Assert.IsInstanceOf<UnknownResponseTool>(tool);
            Assert.AreEqual(typeof(ResponseTool).Assembly, tool.GetType().Assembly);
        }

        [Test]
        public void WithoutProxies_AzureSearchFallsBackToBase()
        {
            // No proxies registered — proves the proxy is what changes behavior.
            ResponseToolsClient client = CreateClient("{\"type\":\"azure_search\",\"index_name\":\"docs\"}");

            ResponseTool tool = client.GetTool("t5");

            Assert.IsInstanceOf<UnknownResponseTool>(tool);
        }

        [Test]
        public void ProxyForDeclaredToolType_RoutesSingleAndNestedCollectionItems()
        {
            const string payload = "{\"type\":\"azure_search\",\"index_name\":\"docs\"}";
            var options = new ModelReaderWriterOptions("J").AddAzureTools();

            ResponseTool? single = ModelReaderWriter.Read<ResponseTool>(BinaryData.FromString(payload), options);
            List<ResponseTool>? list = ModelReaderWriter.Read<List<ResponseTool>>(
                BinaryData.FromString($"[{payload}]"), options);
            List<List<ResponseTool>>? nested = ModelReaderWriter.Read<List<List<ResponseTool>>>(
                BinaryData.FromString($"[[{payload}]]"), options);

            Assert.IsInstanceOf<AzureSearchTool>(single);
            Assert.IsNotNull(list);
            Assert.AreEqual(1, list!.Count);
            Assert.IsInstanceOf<AzureSearchTool>(list[0]);
            Assert.AreEqual(typeof(AzureSearchTool).Assembly, list[0].GetType().Assembly);
            Assert.AreEqual("docs", ((AzureSearchTool)list[0]).IndexName);
            Assert.IsNotNull(nested);
            Assert.IsInstanceOf<AzureSearchTool>(nested![0][0]);
            Assert.AreEqual(typeof(AzureSearchTool).Assembly, nested[0][0].GetType().Assembly);
            Assert.AreEqual("docs", ((AzureSearchTool)nested[0][0]).IndexName);
        }

        [Test]
        public void ProxyForDeclaredToolType_RoutesMixedCollectionAndFallback()
        {
            const string payload = "[{\"type\":\"azure_search\",\"index_name\":\"docs\"}," +
                "{\"type\":\"bing_grounding\",\"market\":\"en-US\"}," +
                "{\"type\":\"function\",\"function_name\":\"get_weather\"}," +
                "{\"type\":\"unrecognized\"}]";
            var options = new ModelReaderWriterOptions("J").AddAzureTools().AddBingTools();

            List<ResponseTool>? tools = ModelReaderWriter.Read<List<ResponseTool>>(
                BinaryData.FromString(payload), options);
            List<List<ResponseTool>>? nested = ModelReaderWriter.Read<List<List<ResponseTool>>>(
                BinaryData.FromString($"[{payload}]"), options);

            Assert.IsNotNull(tools);
            Assert.IsNotNull(nested);
            Assert.AreEqual(1, nested!.Count);
            AssertMixedTools(tools!);
            AssertMixedTools(nested[0]);
        }

        private static void AssertMixedTools(IReadOnlyList<ResponseTool> tools)
        {
            Assert.AreEqual(4, tools.Count);
            Assert.IsInstanceOf<AzureSearchTool>(tools[0]);
            Assert.AreEqual(typeof(AzureSearchTool).Assembly, tools[0].GetType().Assembly);
            Assert.AreEqual("docs", ((AzureSearchTool)tools[0]).IndexName);
            Assert.IsInstanceOf<BingGroundingTool>(tools[1]);
            Assert.AreEqual(typeof(BingGroundingTool).Assembly, tools[1].GetType().Assembly);
            Assert.AreEqual("en-US", ((BingGroundingTool)tools[1]).Market);
            Assert.IsInstanceOf<FunctionTool>(tools[2]);
            Assert.AreEqual(typeof(ResponseTool).Assembly, tools[2].GetType().Assembly);
            Assert.IsInstanceOf<UnknownResponseTool>(tools[3]);
            Assert.AreEqual(typeof(ResponseTool).Assembly, tools[3].GetType().Assembly);
        }

        [Test]
        public void FirstPartyClient_HidesProxy_RoutesAzureSearch()
        {
            // The end user constructs the first-party client and registers NOTHING — the proxy is
            // hidden inside FirstPartyToolsClient. Routing to the first-party subtype still happens.
            var pipelineOptions = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport("{\"type\":\"azure_search\",\"index_name\":\"docs\"}")
            };
            var client = new FirstPartyToolsClient(pipelineOptions);

            ResponseTool tool = client.GetTool("t6");

            Assert.IsInstanceOf<AzureSearchTool>(tool);
            Assert.AreEqual(typeof(AzureSearchTool).Assembly, tool.GetType().Assembly);
            Assert.AreEqual("docs", ((AzureSearchTool)tool).IndexName);
        }

        [Test]
        public void FirstPartyClient_HiddenProxy_CoexistsWithExplicitThirdParty()
        {
            // First-party proxy stays hidden; the customer layers the third-party Bing proxy on top.
            // Each proxy only claims its own discriminator (note 18).
            var pipelineOptions = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport("{\"type\":\"bing_grounding\",\"market\":\"en-US\"}")
            };
            var client = new FirstPartyToolsClient(
                pipelineOptions, o => o.AddProxy<ResponseTool>(new BingGroundingToolProxy()));

            ResponseTool tool = client.GetTool("t7");

            Assert.IsInstanceOf<BingGroundingTool>(tool);
            Assert.AreEqual(typeof(BingGroundingTool).Assembly, tool.GetType().Assembly);
            Assert.AreEqual("en-US", ((BingGroundingTool)tool).Market);
        }

        [Test]
        public void FirstPartyClient_PreservesProxiesConfiguredBeforeConstruction()
        {
            var pipelineOptions = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport("{\"type\":\"bing_grounding\",\"market\":\"en-US\"}")
            };
            pipelineOptions.AddProxy<ResponseTool>(new BingGroundingToolProxy());

            var client = new FirstPartyToolsClient(pipelineOptions);
            ResponseTool tool = client.GetTool("t8");

            Assert.IsInstanceOf<BingGroundingTool>(tool);
            Assert.AreEqual(typeof(BingGroundingTool).Assembly, tool.GetType().Assembly);
            Assert.AreEqual("en-US", ((BingGroundingTool)tool).Market);
        }

        [Test]
        public void SeparateClients_UseOnlyTheirRegisteredProxies()
        {
            const string azurePayload = "{\"type\":\"azure_search\",\"index_name\":\"docs\"}";
            var azureClient = CreateClient(azurePayload, options => options.AddProxy<ResponseTool>(new AzureSearchToolProxy()));
            var bingOnlyClient = CreateClient(azurePayload, options => options.AddProxy<ResponseTool>(new BingGroundingToolProxy()));
            var bingClient = CreateClient(
                "{\"type\":\"bing_grounding\",\"market\":\"en-US\"}",
                options => options.AddProxy<ResponseTool>(new BingGroundingToolProxy()));

            ResponseTool azure = azureClient.GetTool("a");
            ResponseTool noAzure = bingOnlyClient.GetTool("b");
            ResponseTool bing = bingClient.GetTool("c");

            Assert.IsInstanceOf<AzureSearchTool>(azure);
            Assert.AreEqual(typeof(AzureSearchTool).Assembly, azure.GetType().Assembly);
            Assert.IsInstanceOf<UnknownResponseTool>(noAzure);
            Assert.IsInstanceOf<BingGroundingTool>(bing);
            Assert.AreEqual(typeof(BingGroundingTool).Assembly, bing.GetType().Assembly);
        }

        [Test]
        public void SeparateClients_ConcurrentCallsDoNotShareProxyRegistrations()
        {
            const string azurePayload = "{\"type\":\"azure_search\",\"index_name\":\"docs\"}";
            using var barrier = new Barrier(2);
            var azureOptions = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport(azurePayload, processBarrier: barrier)
            };
            azureOptions.AddProxy<ResponseTool>(new AzureSearchToolProxy());
            var bingOnlyOptions = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport(azurePayload, processBarrier: barrier)
            };
            bingOnlyOptions.AddProxy<ResponseTool>(new BingGroundingToolProxy());
            var azureClient = new ResponseToolsClient(azureOptions);
            var bingOnlyClient = new ResponseToolsClient(bingOnlyOptions);

            Task<ResponseTool> azureCall = Task.Factory.StartNew(
                () => azureClient.GetTool("azure"),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Task<ResponseTool> bingOnlyCall = Task.Factory.StartNew(
                () => bingOnlyClient.GetTool("bing"),
                CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Task.WaitAll(azureCall, bingOnlyCall);

            Assert.IsInstanceOf<AzureSearchTool>(azureCall.Result);
            Assert.IsInstanceOf<UnknownResponseTool>(bingOnlyCall.Result);
        }

        [Test]
        public void DisjointProxies_SelectByPayloadWhenRegisteredInReverseOrder()
        {
            var azureClient = CreateClient(
                "{\"type\":\"azure_search\",\"index_name\":\"docs\"}",
                options =>
                {
                    options.AddProxy<ResponseTool>(new BingGroundingToolProxy());
                    options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
                });
            var bingClient = CreateClient(
                "{\"type\":\"bing_grounding\",\"market\":\"en-US\"}",
                options =>
                {
                    options.AddProxy<ResponseTool>(new BingGroundingToolProxy());
                    options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
                });

            Assert.IsInstanceOf<AzureSearchTool>(azureClient.GetTool("a"));
            Assert.IsInstanceOf<BingGroundingTool>(bingClient.GetTool("b"));
        }

        [Test]
        public void ClientOptions_AddProxyRejectsNullAndFrozenOptions()
        {
            var options = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport("{\"type\":\"azure_search\"}")
            };

            Assert.Throws<ArgumentNullException>(
                () => options.AddProxy<ResponseTool>((IPersistableModel<ResponseTool>)null!));
            Assert.Throws<ArgumentNullException>(
                () => options.AddProxy<ResponseTool>((ConditionalModelProxy<ResponseTool>)null!));

            ClientPipeline.Create(options);

            Assert.Throws<InvalidOperationException>(
                () => options.AddProxy<ResponseTool>(new AzureSearchToolProxy()));
        }

        [Test]
        public void ClientOptions_DoNotExposeAModelReaderWriterOptionsSetter()
        {
            Assert.IsNull(typeof(ClientPipelineOptions)
                .GetProperty(nameof(ClientPipelineOptions.ModelReaderWriterOptions))!.GetSetMethod());
        }

        [Test]
        public void ClientConstruction_SnapshotsProxyRegistrations()
        {
            var options = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport("{\"type\":\"bing_grounding\",\"market\":\"en-US\"}")
            };
            options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
            var client = new ResponseToolsClient(options);

            options.ModelReaderWriterOptions!.AddProxy<ResponseTool>(new BingGroundingToolProxy());

            Assert.IsInstanceOf<UnknownResponseTool>(client.GetTool("snapshot"));
        }

        [Test]
        public void ClientOptionsClone_SeparatesProxyRegistrations()
        {
            var options = new ClientPipelineOptions
            {
                Transport = new CannedResponseTransport("{\"type\":\"bing_grounding\",\"market\":\"en-US\"}")
            };
            options.AddProxy<ResponseTool>(new AzureSearchToolProxy());
            ClientPipelineOptions clone = options.Clone();
            options.ModelReaderWriterOptions!.AddProxy<ResponseTool>(new BingGroundingToolProxy());

            var client = new ResponseToolsClient(clone);

            Assert.IsInstanceOf<UnknownResponseTool>(client.GetTool("clone"));
        }

        #region Write resolution for proxies registered on a base type

        private const string DefaultSearchJson = "{\"type\":\"azure_search\",\"index_name\":\"docs\"}";

        private static string Sentinel(string name) => $"{{\"sentinel\":\"{name}\"}}";

        [Test]
        public void BaseRegistration_WriteOfDeclaredBase_UsesConditionalProxyForDerivedInstance()
        {
            var options = new ModelReaderWriterOptions("J");
            var proxy = new SentinelToolProxy("base", canHandle: tool => tool is AzureSearchTool);
            options.AddProxy<ResponseTool>(proxy);
            var tool = new AzureSearchTool("docs");

            BinaryData written = ModelReaderWriter.Write<ResponseTool>(tool, options);

            Assert.AreEqual(Sentinel("base"), written.ToString());
            CollectionAssert.AreEqual(new[] { typeof(AzureSearchTool) }, proxy.Consulted);
            Assert.AreSame(tool, proxy.ProxiedModelAtWrite);
        }

        [Test]
        public void BaseRegistration_WriteWithoutDeclaredBase_UsesProxyForDerivedInstance()
        {
            var options = new ModelReaderWriterOptions("J");
            options.AddProxy<ResponseTool>(new SentinelToolProxy("base", canHandle: tool => tool is AzureSearchTool));

            Assert.AreEqual(Sentinel("base"), ModelReaderWriter.Write(new AzureSearchTool("docs"), options).ToString());
            Assert.AreEqual(Sentinel("base"), ModelReaderWriter.Write((object)new AzureSearchTool("docs"), options).ToString());
        }

        [Test]
        public void BaseRegistration_ResolveProxyOverloads_ReturnBaseProxyAndSetProxiedModel()
        {
            var options = new ModelReaderWriterOptions("J", ModelReaderWriterReflectionContext.Default);
            var proxy = new SentinelToolProxy("base", canHandle: tool => tool is AzureSearchTool);
            options.AddProxy<ResponseTool>(proxy);
            var tool = new AzureSearchTool("docs");

            IJsonModel<ResponseTool> jsonResolved = options.ResolveProxy((IJsonModel<ResponseTool>)tool);
            Assert.AreSame(proxy.Model, jsonResolved);
            Assert.AreSame(tool, options.ProxiedModel);

            IPersistableModel<ResponseTool> persistableResolved = options.ResolveProxy((IPersistableModel<ResponseTool>)tool);
            Assert.AreSame(proxy.Model, persistableResolved);
            Assert.AreSame(tool, options.ProxiedModel);

            // Declined instances keep the original model and clear ProxiedModel.
            var function = new FunctionTool("get_weather");
            Assert.AreSame(function, options.ResolveProxy((IJsonModel<ResponseTool>)function));
            Assert.IsNull(options.ProxiedModel);
        }

        [Test]
        public void BaseRegistration_NonGenericPaths_UseBaseProxy()
        {
            var options = new ModelReaderWriterOptions("J");
            options.AddProxy<ResponseTool>(new SentinelToolProxy("base", canHandle: tool => tool is AzureSearchTool));
            var tools = new List<ResponseTool> { new AzureSearchTool("docs"), new FunctionTool("get_weather") };

            string collection = ModelReaderWriter.Write(tools, options).ToString();

            Assert.AreEqual($"[{Sentinel("base")},{{\"type\":\"function\",\"function_name\":\"get_weather\"}}]", collection);

            var serializerOptions = new JsonSerializerOptions { Converters = { new JsonModelConverter(options) } };
            string converted = JsonSerializer.Serialize((IJsonModel<object>)new AzureSearchTool("docs"), serializerOptions);

            Assert.AreEqual(Sentinel("base"), converted);
        }

        [Test]
        public void ExactTypeRegistration_TakesPrecedenceOverBaseRegistration()
        {
            var options = new ModelReaderWriterOptions("J");
            var baseProxy = new SentinelToolProxy("base", canHandle: _ => true);
            options.AddProxy<ResponseTool>(baseProxy);
            options.AddProxy<AzureSearchTool>(new SentinelModel<AzureSearchTool>("exact"));

            Assert.AreEqual(Sentinel("exact"), ModelReaderWriter.Write<ResponseTool>(new AzureSearchTool("docs"), options).ToString());
            Assert.AreEqual(Sentinel("exact"), ModelReaderWriter.Write(new List<ResponseTool> { new AzureSearchTool("docs") }, options).ToString().Trim('[', ']'));
            Assert.AreEqual(Sentinel("base"), ModelReaderWriter.Write<ResponseTool>(new FunctionTool("f"), options).ToString());
            CollectionAssert.DoesNotContain(baseProxy.Consulted, typeof(AzureSearchTool));
        }

        [Test]
        public void ExactTypeRegistration_ThatDeclines_FallsThroughToBaseRegistration()
        {
            var options = new ModelReaderWriterOptions("J");
            var exact = new SentinelShapeProxy<Circle>("exact", canHandle: _ => false);
            options.AddProxy<Circle>(exact);
            options.AddProxy<Shape>(new SentinelModel<Shape>("base"));

            Assert.AreEqual(Sentinel("base"), ModelReaderWriter.Write<Shape>(new Circle(), options).ToString());
            Assert.AreEqual(1, exact.CanHandleCalls);
        }

        [Test]
        public void ConditionalBaseProxy_ThatDeclinesDerivedType_KeepsDefaultWrite()
        {
            var options = new ModelReaderWriterOptions("J");
            var proxy = new SentinelToolProxy("base", canHandle: tool => tool is FunctionTool);
            options.AddProxy<ResponseTool>(proxy);

            BinaryData written = ModelReaderWriter.Write<ResponseTool>(new AzureSearchTool("docs"), options);

            Assert.AreEqual(DefaultSearchJson, written.ToString());
            CollectionAssert.AreEqual(new[] { typeof(AzureSearchTool) }, proxy.Consulted);
        }

        [Test]
        public void DirectBaseProxy_CapturesEveryDerivedType()
        {
            var options = new ModelReaderWriterOptions("J");
            options.AddProxy<ResponseTool>(new SentinelModel<ResponseTool>("direct"));

            Assert.AreEqual(Sentinel("direct"), ModelReaderWriter.Write<ResponseTool>(new AzureSearchTool("docs"), options).ToString());
            Assert.AreEqual(Sentinel("direct"), ModelReaderWriter.Write<ResponseTool>(new FunctionTool("f"), options).ToString());
        }

        // Writes a distinct sentinel document so a test can tell the proxy (not the original model) wrote.
        private sealed class SentinelModel<T> : IJsonModel<T>
        {
            private readonly string _name;

            public SentinelModel(string name) => _name = name;

            public object? ProxiedModelAtWrite { get; private set; }

            T IJsonModel<T>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => throw new NotSupportedException();

            void IJsonModel<T>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
            {
                ProxiedModelAtWrite = options.ProxiedModel;
                writer.WriteStartObject();
                writer.WriteString("sentinel"u8, _name);
                writer.WriteEndObject();
            }

            T IPersistableModel<T>.Create(BinaryData data, ModelReaderWriterOptions options) => throw new NotSupportedException();

            BinaryData IPersistableModel<T>.Write(ModelReaderWriterOptions options) => BinaryData.FromString(Sentinel(_name));

            string IPersistableModel<T>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
        }

        private sealed class SentinelToolProxy : ConditionalModelProxy<ResponseTool>
        {
            private readonly Func<ResponseTool, bool> _canHandle;
            private readonly SentinelModel<ResponseTool> _model;

            public SentinelToolProxy(string name, Func<ResponseTool, bool> canHandle)
                : this(new SentinelModel<ResponseTool>(name), canHandle)
            {
            }

            private SentinelToolProxy(SentinelModel<ResponseTool> model, Func<ResponseTool, bool> canHandle) : base(model)
            {
                _model = model;
                _canHandle = canHandle;
            }

            public List<Type> Consulted { get; } = new();

            public object? ProxiedModelAtWrite => _model.ProxiedModelAtWrite;

            public override bool CanHandle(ResponseTool model, ModelReaderWriterOptions options, ModelReaderWriterContext context)
            {
                Consulted.Add(model.GetType());
                return _canHandle(model);
            }
        }

        private class Shape : IJsonModel<Shape>
        {
            Shape IJsonModel<Shape>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => throw new NotSupportedException();

            void IJsonModel<Shape>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
            {
                writer.WriteStartObject();
                writer.WriteEndObject();
            }

            Shape IPersistableModel<Shape>.Create(BinaryData data, ModelReaderWriterOptions options) => throw new NotSupportedException();

            BinaryData IPersistableModel<Shape>.Write(ModelReaderWriterOptions options) => BinaryData.FromString("{}");

            string IPersistableModel<Shape>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
        }

        private sealed class Circle : Shape, IJsonModel<Circle>
        {
            Circle IJsonModel<Circle>.Create(ref Utf8JsonReader reader, ModelReaderWriterOptions options) => throw new NotSupportedException();

            void IJsonModel<Circle>.Write(Utf8JsonWriter writer, ModelReaderWriterOptions options)
            {
                writer.WriteStartObject();
                writer.WriteEndObject();
            }

            Circle IPersistableModel<Circle>.Create(BinaryData data, ModelReaderWriterOptions options) => throw new NotSupportedException();

            BinaryData IPersistableModel<Circle>.Write(ModelReaderWriterOptions options) => BinaryData.FromString("{}");

            string IPersistableModel<Circle>.GetFormatFromOptions(ModelReaderWriterOptions options) => "J";
        }

        private sealed class SentinelShapeProxy<T> : ConditionalModelProxy<T>
            where T : IPersistableModel<T>
        {
            private readonly Func<T, bool> _canHandle;

            public SentinelShapeProxy(string name, Func<T, bool> canHandle) : base(new SentinelModel<T>(name))
            {
                _canHandle = canHandle;
            }

            public int CanHandleCalls { get; private set; }

            public override bool CanHandle(T model, ModelReaderWriterOptions options, ModelReaderWriterContext context)
            {
                CanHandleCalls++;
                return _canHandle(model);
            }
        }

        #endregion
    }
}

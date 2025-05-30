// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager.HybridConnectivity.Models;
using NUnit.Framework;

namespace Azure.ResourceManager.HybridConnectivity.Samples
{
    public partial class Sample_PublicCloudConnectorSolutionConfigurationCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_SolutionConfigurationsCreateOrUpdate()
        {
            // Generated from example definition: 2024-12-01/SolutionConfigurations_CreateOrUpdate.json
            // this example is just showing the usage of "SolutionConfiguration_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // get the collection of this PublicCloudConnectorSolutionConfigurationResource
            string resourceUri = "ymuj";
            PublicCloudConnectorSolutionConfigurationCollection collection = client.GetPublicCloudConnectorSolutionConfigurations(new ResourceIdentifier(resourceUri));

            // invoke the operation
            string solutionConfiguration = "keebwujt";
            PublicCloudConnectorSolutionConfigurationData data = new PublicCloudConnectorSolutionConfigurationData
            {
                Properties = new PublicCloudConnectorSolutionConfigurationProperties("nmtqllkyohwtsthxaimsye")
                {
                    SolutionSettings = new PublicCloudConnectorSolutionSettings(),
                },
            };
            ArmOperation<PublicCloudConnectorSolutionConfigurationResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, solutionConfiguration, data);
            PublicCloudConnectorSolutionConfigurationResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            PublicCloudConnectorSolutionConfigurationData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_SolutionConfigurationsGet()
        {
            // Generated from example definition: 2024-12-01/SolutionConfigurations_Get.json
            // this example is just showing the usage of "SolutionConfiguration_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // get the collection of this PublicCloudConnectorSolutionConfigurationResource
            string resourceUri = "ymuj";
            PublicCloudConnectorSolutionConfigurationCollection collection = client.GetPublicCloudConnectorSolutionConfigurations(new ResourceIdentifier(resourceUri));

            // invoke the operation
            string solutionConfiguration = "tks";
            PublicCloudConnectorSolutionConfigurationResource result = await collection.GetAsync(solutionConfiguration);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            PublicCloudConnectorSolutionConfigurationData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetAll_SolutionConfigurationsList()
        {
            // Generated from example definition: 2024-12-01/SolutionConfigurations_List.json
            // this example is just showing the usage of "SolutionConfiguration_List" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // get the collection of this PublicCloudConnectorSolutionConfigurationResource
            string resourceUri = "ymuj";
            PublicCloudConnectorSolutionConfigurationCollection collection = client.GetPublicCloudConnectorSolutionConfigurations(new ResourceIdentifier(resourceUri));

            // invoke the operation and iterate over the result
            await foreach (PublicCloudConnectorSolutionConfigurationResource item in collection.GetAllAsync())
            {
                // the variable item is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                PublicCloudConnectorSolutionConfigurationData resourceData = item.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }

            Console.WriteLine("Succeeded");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_SolutionConfigurationsGet()
        {
            // Generated from example definition: 2024-12-01/SolutionConfigurations_Get.json
            // this example is just showing the usage of "SolutionConfiguration_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // get the collection of this PublicCloudConnectorSolutionConfigurationResource
            string resourceUri = "ymuj";
            PublicCloudConnectorSolutionConfigurationCollection collection = client.GetPublicCloudConnectorSolutionConfigurations(new ResourceIdentifier(resourceUri));

            // invoke the operation
            string solutionConfiguration = "tks";
            bool result = await collection.ExistsAsync(solutionConfiguration);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_SolutionConfigurationsGet()
        {
            // Generated from example definition: 2024-12-01/SolutionConfigurations_Get.json
            // this example is just showing the usage of "SolutionConfiguration_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // get the collection of this PublicCloudConnectorSolutionConfigurationResource
            string resourceUri = "ymuj";
            PublicCloudConnectorSolutionConfigurationCollection collection = client.GetPublicCloudConnectorSolutionConfigurations(new ResourceIdentifier(resourceUri));

            // invoke the operation
            string solutionConfiguration = "tks";
            NullableResponse<PublicCloudConnectorSolutionConfigurationResource> response = await collection.GetIfExistsAsync(solutionConfiguration);
            PublicCloudConnectorSolutionConfigurationResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                PublicCloudConnectorSolutionConfigurationData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}

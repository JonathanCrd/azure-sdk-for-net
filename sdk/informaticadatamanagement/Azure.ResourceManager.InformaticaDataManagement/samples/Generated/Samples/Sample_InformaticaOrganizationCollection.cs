// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager.InformaticaDataManagement.Models;
using Azure.ResourceManager.Resources;
using NUnit.Framework;

namespace Azure.ResourceManager.InformaticaDataManagement.Samples
{
    public partial class Sample_InformaticaOrganizationCollection
    {
        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_OrganizationsCreateOrUpdate()
        {
            // Generated from example definition: 2024-05-08/Organizations_CreateOrUpdate_MaximumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "C";
            InformaticaOrganizationData data = new InformaticaOrganizationData(new AzureLocation("pamjoudtssthlbhrnfjidr"))
            {
                Properties = new InformaticaOrganizationProperties
                {
                    InformaticaProperties = new InformaticaProperties
                    {
                        OrganizationId = "wtdmhlwhkvgqdumaehgfgiqcxgnqpx",
                        OrganizationName = "nomzbvwe",
                        InformaticaRegion = "zfqodqpbeflhedypiijdkc",
                        SingleSignOnUri = new Uri("https://contoso.com/singlesignon"),
                    },
                    MarketplaceDetails = new InformaticaMarketplaceDetails(new InformaticaOfferDetails("zajxpfacudwongxjvnnuhhpygmnydchgowjccyuzsjonegmqxcqqpnzafanggowfqdixnnutyfvmvwrkx", "cwswcfwmzhjcoksmueukegwaptvpcmbfyvixfhvgwnjyblqivqdkkwkunkgimiopwwkvgnwclmajhuty", "jfnemevyivtlxhectiutdavdgfyidolivuojumdzckp", "iaoxgaitteuoqgujkgxbdgryaobtkjjecuvchwutntrvmuorikrbqqegmelenbewhakiysprrnovjixyxrikscaptrbapbdspu", "tcvvsxdjnjlfmjhmvwklptdmxetnzydxyuhfqchoubmtoeqbchnfxoxqzezlgpxdnzyvzgkynjxzzgetkqccxvpzahxattluqdipvbdktqmndfefitzuifqjpschzlbvixnvznkmmgjwvkplfhemnapsewgqxggdzdokryhv")
                    {
                        TermUnit = "gjwmgevrblbosuogsvfspsgspetbnxaygkbelvadpgwiywl",
                    })
                    {
                        MarketplaceSubscriptionId = "ovenlecocg",
                    },
                    UserDetails = new InformaticaUserDetails
                    {
                        FirstName = "appvdclawzfjntdfdftjevlhvzropnxqtnypid",
                        LastName = "nzirbvzmkxtbrlamyatlcszebxgcyncxoascojsmacwvjsjvn",
                        EmailAddress = "7_-46@13D--3.m-4x-.11.c-9-.DHLYFc",
                        Upn = "undljch",
                        PhoneNumber = "fvcjylxlmhdnshsgywnzlyvshu",
                    },
                    CompanyDetails = new InformaticaCompanyDetails
                    {
                        CompanyName = "xszcggknokhw",
                        OfficeAddress = "sbttzwyajgdbsvipuiclbzvkcvwyil",
                        Country = "gwkcpnwyaqc",
                        Domain = "utcxetzzpmbvwmjrvphqngvp",
                        Business = "pucosrtjv",
                        NumberOfEmployees = 25,
                    },
                    LinkOrganizationToken = "jjfouhoqpumjvrdsfbimgcy",
                },
                Tags =
{
["key8430"] = "cagshqtjlxtqqhdwtchokvxszybp"
},
            };
            ArmOperation<InformaticaOrganizationResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, organizationName, data);
            InformaticaOrganizationResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            InformaticaOrganizationData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task CreateOrUpdate_OrganizationsCreateOrUpdateMin()
        {
            // Generated from example definition: 2024-05-08/Organizations_CreateOrUpdate_MinimumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_CreateOrUpdate" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "n6v";
            InformaticaOrganizationData data = new InformaticaOrganizationData(new AzureLocation("pamjoudtssthlbhrnfjidr"));
            ArmOperation<InformaticaOrganizationResource> lro = await collection.CreateOrUpdateAsync(WaitUntil.Completed, organizationName, data);
            InformaticaOrganizationResource result = lro.Value;

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            InformaticaOrganizationData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_OrganizationsGet()
        {
            // Generated from example definition: 2024-05-08/Organizations_Get_MaximumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "Sg";
            InformaticaOrganizationResource result = await collection.GetAsync(organizationName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            InformaticaOrganizationData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Get_OrganizationsGetMin()
        {
            // Generated from example definition: 2024-05-08/Organizations_Get_MinimumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "q";
            InformaticaOrganizationResource result = await collection.GetAsync(organizationName);

            // the variable result is a resource, you could call other operations on this instance as well
            // but just for demo, we get its data from this resource instance
            InformaticaOrganizationData resourceData = result.Data;
            // for demo we just print out the id
            Console.WriteLine($"Succeeded on id: {resourceData.Id}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_OrganizationsGet()
        {
            // Generated from example definition: 2024-05-08/Organizations_Get_MaximumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "Sg";
            bool result = await collection.ExistsAsync(organizationName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task Exists_OrganizationsGetMin()
        {
            // Generated from example definition: 2024-05-08/Organizations_Get_MinimumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "q";
            bool result = await collection.ExistsAsync(organizationName);

            Console.WriteLine($"Succeeded: {result}");
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_OrganizationsGet()
        {
            // Generated from example definition: 2024-05-08/Organizations_Get_MaximumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "Sg";
            NullableResponse<InformaticaOrganizationResource> response = await collection.GetIfExistsAsync(organizationName);
            InformaticaOrganizationResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                InformaticaOrganizationData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }

        [Test]
        [Ignore("Only validating compilation of examples")]
        public async Task GetIfExists_OrganizationsGetMin()
        {
            // Generated from example definition: 2024-05-08/Organizations_Get_MinimumSet_Gen.json
            // this example is just showing the usage of "InformaticaOrganizationResource_Get" operation, for the dependent resources, they will have to be created separately.

            // get your azure access token, for more details of how Azure SDK get your access token, please refer to https://learn.microsoft.com/en-us/dotnet/azure/sdk/authentication?tabs=command-line
            TokenCredential cred = new DefaultAzureCredential();
            // authenticate your client
            ArmClient client = new ArmClient(cred);

            // this example assumes you already have this ResourceGroupResource created on azure
            // for more information of creating ResourceGroupResource, please refer to the document of ResourceGroupResource
            string subscriptionId = "3599DA28-E346-4D9F-811E-189C0445F0FE";
            string resourceGroupName = "rgopenapi";
            ResourceIdentifier resourceGroupResourceId = ResourceGroupResource.CreateResourceIdentifier(subscriptionId, resourceGroupName);
            ResourceGroupResource resourceGroupResource = client.GetResourceGroupResource(resourceGroupResourceId);

            // get the collection of this InformaticaOrganizationResource
            InformaticaOrganizationCollection collection = resourceGroupResource.GetInformaticaOrganizations();

            // invoke the operation
            string organizationName = "q";
            NullableResponse<InformaticaOrganizationResource> response = await collection.GetIfExistsAsync(organizationName);
            InformaticaOrganizationResource result = response.HasValue ? response.Value : null;

            if (result == null)
            {
                Console.WriteLine("Succeeded with null as result");
            }
            else
            {
                // the variable result is a resource, you could call other operations on this instance as well
                // but just for demo, we get its data from this resource instance
                InformaticaOrganizationData resourceData = result.Data;
                // for demo we just print out the id
                Console.WriteLine($"Succeeded on id: {resourceData.Id}");
            }
        }
    }
}

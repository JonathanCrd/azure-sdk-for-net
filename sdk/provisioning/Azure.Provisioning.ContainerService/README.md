# Azure Provisioning ContainerService client library for .NET

Azure.Provisioning.ContainerService simplifies declarative resource provisioning in .NET.

## Getting started

### Install the package

Install the client library for .NET with [NuGet](https://www.nuget.org/ ):

```dotnetcli
dotnet add package Azure.Provisioning.ContainerService --prerelease
```

### Prerequisites

> You must have an [Azure subscription](https://azure.microsoft.com/free/dotnet/).

### Authenticate the Client

## Key concepts

This library allows you to specify your infrastructure in a declarative style using dotnet.  You can then use azd to deploy your infrastructure to Azure directly without needing to write or maintain bicep or arm templates.

## Examples

### Create An AKS Cluster

This example demonstrates how to create an Azure Kubernetes Service (AKS) cluster with SSH authentication and system agent pool, based on the [Azure quickstart template](https://github.com/Azure/azure-quickstart-templates/blob/master/quickstarts/microsoft.kubernetes/aks/main.bicep).

```C# Snippet:ContainerServiceBasic
Infrastructure infra = new();

ProvisioningParameter dnsPrefix = new(nameof(dnsPrefix), typeof(string));
infra.Add(dnsPrefix);

ProvisioningParameter linuxAdminUsername = new(nameof(linuxAdminUsername), typeof(string));
infra.Add(linuxAdminUsername);

ProvisioningParameter sshRsaPublicKey = new(nameof(sshRsaPublicKey), typeof(string));
infra.Add(sshRsaPublicKey);

ContainerServiceManagedCluster aks =
    new(nameof(aks))
    {
        ClusterIdentity = new ManagedClusterIdentity { ResourceIdentityType = ManagedServiceIdentityType.SystemAssigned },
        DnsPrefix = dnsPrefix,
        LinuxProfile =
            new ContainerServiceLinuxProfile
            {
                AdminUsername = linuxAdminUsername,
                SshPublicKeys =
                {
                    new ContainerServiceSshPublicKey { KeyData = sshRsaPublicKey }
                }
            },
        AgentPoolProfiles =
        {
            new ManagedClusterAgentPoolProfile
            {
                Name = "agentpool",
                VmSize = "standard_d2s_v3",
                OSDiskSizeInGB = 0, // 0 means default disk size for that agent
                Count = 3,
                OSType = ContainerServiceOSType.Linux,
                Mode = AgentPoolMode.System
            }
        }
    };
infra.Add(aks);
```

## Troubleshooting

-   File an issue via [GitHub Issues](https://github.com/Azure/azure-sdk-for-net/issues).
-   Check [previous questions](https://stackoverflow.com/questions/tagged/azure+.net) or ask new ones on Stack Overflow using Azure and .NET tags.

## Next steps

## Contributing

For details on contributing to this repository, see the [contributing
guide][cg].

This project welcomes contributions and suggestions. Most contributions
require you to agree to a Contributor License Agreement (CLA) declaring
that you have the right to, and actually do, grant us the rights to use
your contribution. For details, visit <https://cla.microsoft.com>.

When you submit a pull request, a CLA-bot will automatically determine
whether you need to provide a CLA and decorate the PR appropriately
(for example, label, comment). Follow the instructions provided by the
bot. You'll only need to do this action once across all repositories
using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct][coc]. For
more information, see the [Code of Conduct FAQ][coc_faq] or contact
<opencode@microsoft.com> with any other questions or comments.

<!-- LINKS -->
[cg]: https://github.com/Azure/azure-sdk-for-net/blob/main/sdk/resourcemanager/Azure.ResourceManager/docs/CONTRIBUTING.md
[coc]: https://opensource.microsoft.com/codeofconduct/
[coc_faq]: https://opensource.microsoft.com/codeofconduct/faq/

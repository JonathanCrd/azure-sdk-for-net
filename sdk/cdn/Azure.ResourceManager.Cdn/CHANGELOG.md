# Release History

## 1.5.0-beta.1 (Unreleased)

### Features Added

### Breaking Changes

### Bugs Fixed

### Other Changes

## 1.4.0 (2025-05-10)

### Features Added

- Updated API version to 2025-04-15
- Added support for cipher

## 1.3.1 (2025-03-11)

### Features Added

- Exposed `JsonModelWriteCore` for model serialization procedure.

## 1.3.0 (2024-04-30)

### Features Added

- Enable the new model serialization by using the System.ClientModel, refer this [document](https://aka.ms/azsdk/net/mrw) for more details.
- Add `ArmOperation.Rehydrate` and `ArmOperation.Rehydrate<T>` static methods to rehydrate a long-running operation.
- Add canMigrate API
- Add Migrate API
- Add log-scrubbing support for profile
- Add new customization for CDN Endpoint.
- Use DeepCreatedCustomDomain for CDN Endpoint API to replace CustomDomain
- Add secretSource support for AzureFirstPartyManagedCertificateProperties
- Fix ManagedRuleGroupOverrideSetting error in comment
- Add ProfileChangeSkuWafMapping 
- Add ManagedServiceIdentity support for profile
- Add ValidateSecret

## 1.2.0 (2023-11-21)

### Features Added

- Enable mocking for extension methods, refer this [document](https://aka.ms/azsdk/net/mocking) for more details.

### Other Changes

- Upgraded dependent `Azure.ResourceManager` to 1.9.0.

## 1.2.0-beta.1 (2023-05-29)

### Features Added

- Enable the model factory feature for model mocking, more information can be found [here](https://azure.github.io/azure-sdk/dotnet_introduction.html#dotnet-mocking-factory-builder).

### Other Changes

- Upgraded dependent Azure.Core to 1.32.0.
- Upgraded dependent Azure.ResourceManager to 1.6.0.

## 1.1.0 (2023-02-14)

### Features Added

- Introduced property bag for the methods with more than 5 parameters.

### Other Changes

- Upgraded dependent `Azure.Core` to `1.28.0`.
- Upgraded dependent `Azure.ResourceManager` to `1.4.0`.

## 1.0.1 (2022-09-13)

### Breaking Changes

Modified the following classes to abstract classes and changed their constructors from public to protected:
- `CustomDomainHttpsContent`
- `DeliveryRuleAction`
- `DeliveryRuleCondition`
- `FrontDoorSecretProperties`
- `SecurityPolicyProperties`

### Other Changes

- Upgraded dependent `Azure.ResourceManager` to 1.3.1.
- Optimized the implementation of methods related to tag operations.

## 1.0.0 (2022-07-11)
This release is the first stable release of the Azure Cdn management library.

### Features Added

- Added Update methods in resource classes.

### Breaking Changes

Polishing since last public beta release:
- Changed all the `Afd` prefix to `FrontDoor` prefix.
- Corrected the format of all `Guid` type properties / parameters.
- Corrected the format of all `ResourceIdentifier` type properties / parameters.
- Corrected the format of all `ResouceType` type properties / parameters.
- Corrected the format of all `ETag` type properties / parameters.
- Corrected the format of all `AzureLocation` type properties / parameters.
- Corrected the format of all binary type properties / parameters.
- Corrected all acronyms that not follow [.Net Naming Guidelines](https://learn.microsoft.com/dotnet/standard/design-guidelines/naming-guidelines).
- Corrected enumeration name by following [Naming Enumerations Rule](https://learn.microsoft.com/dotnet/standard/design-guidelines/names-of-classes-structs-and-interfaces#naming-enumerations).
- Corrected the suffix of `DateTimeOffset` properties / parameters.
- Optimized the name of some models and properties.
- Flattened property from a read-only model no longer has setters.

### Bugs Fixed

- Corrected the return type of `EnableCustomHttps` and `DisableCustomHttps` method.

### Other Changes

- Upgraded dependent `Azure.ResourceManager` to 1.2.0
- Upgraded dependent `Azure.Core` to 1.25.0

## 1.0.0-beta.5 (2022-04-08)

### Breaking Changes

- Simplify `type` property names.
- Normalized the body parameter type names for PUT / POST / PATCH operations if it is only used as input.

### Other Changes

- Upgrade dependency to Azure.ResourceManager 1.0.0

## 1.0.0-beta.4 (2022-03-31)

### Breaking Changes

- Now all the resource classes would have a `Resource` suffix (if it previously does not have one).
- Renamed some models to more comprehensive names.
- `bool waitForCompletion` parameter in all long running operations were changed to `WaitUntil waitUntil`.
- All properties of the type `object` were changed to `BinaryData`.
- Removed `GetIfExists` methods from all the resource classes.

## 1.0.0-beta.3 (2022-02-08)

### Features Added

- Bump API version to `2021-06-01`

### Breaking Changes

- waitForCompletion is now a required parameter and moved to the first parameter in LRO operations.
- Removed GetAllAsGenericResources in [Resource]Collections.
- Added Resource constructor to use ArmClient for ClientContext information and removed previous constructors with parameters
- Renaming: CheckNameAvailability renamed to CheckCdnNameAvailability, CheckNameAvailabilityWithSubscription renamed to CheckCdnNameAvailabilityWithSubscription, DeliveryRuleActionAutoGenerated renamed to DeliveryRuleAction

## 1.0.0-beta.2 (2021-12-28)

### Features Added

- Added `CreateResourceIdentifier` for each resource class

### Breaking Changes

- Renamed `CheckIfExists` to `Exists` for each resource collection class
- Renamed `Get{Resource}ByName` to `Get{Resource}AsGenericResources` in `SubscriptionExtensions`

## 1.0.0-beta.1 (2021-11-09)

### Breaking Changes

New design of track 2 initial commit.

### Package Name

The package name has been changed from `Microsoft.Azure.Management.Cdn` to `Azure.ResourceManager.Cdn`.

### General New Features

This package follows the [new Azure SDK guidelines](https://azure.github.io/azure-sdk/general_introduction.html), and provides many core capabilities:

    - Support MSAL.NET, Azure.Identity is out of box for supporting MSAL.NET.
    - Support [OpenTelemetry](https://opentelemetry.io/) for distributed tracing.
    - HTTP pipeline with custom policies.
    - Better error-handling.
    - Support uniform telemetry across all languages.

This package is a Public Preview version, so expect incompatible changes in subsequent releases as we improve the product. To provide feedback, submit an issue in our [Azure SDK for .NET GitHub repo](https://github.com/Azure/azure-sdk-for-net/issues).

> NOTE: For more information about unified authentication, please refer to [Microsoft Azure Identity documentation for .NET](https://learn.microsoft.com/dotnet/api/overview/azure/identity-readme?view=azure-dotnet).

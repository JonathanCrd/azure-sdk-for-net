// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable enable

using Azure.Provisioning.Primitives;

namespace Azure.Provisioning.OperationalInsights;

/// <summary>
/// The cluster sku definition.
/// </summary>
public partial class OperationalInsightsClusterSku : ProvisionableConstruct
{
    /// <summary>
    /// The capacity value.
    /// </summary>
    public BicepValue<OperationalInsightsClusterCapacity> Capacity 
    {
        get { Initialize(); return _capacity!; }
        set { Initialize(); _capacity!.Assign(value); }
    }
    private BicepValue<OperationalInsightsClusterCapacity>? _capacity;

    /// <summary>
    /// The name of the SKU.
    /// </summary>
    public BicepValue<OperationalInsightsClusterSkuName> Name 
    {
        get { Initialize(); return _name!; }
        set { Initialize(); _name!.Assign(value); }
    }
    private BicepValue<OperationalInsightsClusterSkuName>? _name;

    /// <summary>
    /// Creates a new OperationalInsightsClusterSku.
    /// </summary>
    public OperationalInsightsClusterSku()
    {
    }

    /// <summary>
    /// Define all the provisionable properties of
    /// OperationalInsightsClusterSku.
    /// </summary>
    protected override void DefineProvisionableProperties()
    {
        base.DefineProvisionableProperties();
        _capacity = DefineProperty<OperationalInsightsClusterCapacity>("Capacity", ["capacity"]);
        _name = DefineProperty<OperationalInsightsClusterSkuName>("Name", ["name"]);
    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

using Azure.Provisioning;
using Azure.Provisioning.Primitives;
using System;

namespace Azure.Provisioning.EventGrid;

/// <summary>
/// StringNotContains Advanced Filter.
/// </summary>
public partial class StringNotContainsAdvancedFilter : AdvancedFilter
{
    /// <summary>
    /// The set of filter values.
    /// </summary>
    public BicepList<string> Values { get => _values; set => _values.Assign(value); }
    private readonly BicepList<string> _values;

    /// <summary>
    /// Creates a new StringNotContainsAdvancedFilter.
    /// </summary>
    public StringNotContainsAdvancedFilter() : base()
    {
        BicepValue<string>.DefineProperty(this, "operatorType", ["operatorType"], defaultValue: "StringNotContains");
        _values = BicepList<string>.DefineProperty(this, "Values", ["values"]);
    }
}

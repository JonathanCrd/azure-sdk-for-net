// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable enable

using Azure.Provisioning.Primitives;
using System;

namespace Azure.Provisioning.CosmosDB;

/// <summary>
/// A CosmosDB Cassandra API data source/sink.
/// </summary>
public partial class CosmosCassandraDataTransferDataSourceSink : BaseCosmosDataTransferDataSourceSink
{
    /// <summary>
    /// Gets or sets the keyspace name.
    /// </summary>
    public BicepValue<string> KeyspaceName 
    {
        get { Initialize(); return _keyspaceName!; }
        set { Initialize(); _keyspaceName!.Assign(value); }
    }
    private BicepValue<string>? _keyspaceName;

    /// <summary>
    /// Gets or sets the table name.
    /// </summary>
    public BicepValue<string> TableName 
    {
        get { Initialize(); return _tableName!; }
        set { Initialize(); _tableName!.Assign(value); }
    }
    private BicepValue<string>? _tableName;

    /// <summary>
    /// Creates a new CosmosCassandraDataTransferDataSourceSink.
    /// </summary>
    public CosmosCassandraDataTransferDataSourceSink() : base()
    {
    }

    /// <summary>
    /// Define all the provisionable properties of
    /// CosmosCassandraDataTransferDataSourceSink.
    /// </summary>
    protected override void DefineProvisionableProperties()
    {
        base.DefineProvisionableProperties();
        DefineProperty<string>("component", ["component"], defaultValue: "CosmosDBCassandra");
        _keyspaceName = DefineProperty<string>("KeyspaceName", ["keyspaceName"]);
        _tableName = DefineProperty<string>("TableName", ["tableName"]);
    }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure.Core;
using Azure.ResourceManager.Models;

namespace Azure.ResourceManager.SecurityInsights.Models
{
    /// <summary> Represents scheduled alert rule template. </summary>
    public partial class ScheduledAlertRuleTemplate : SecurityInsightsAlertRuleTemplateData
    {
        /// <summary> Initializes a new instance of <see cref="ScheduledAlertRuleTemplate"/>. </summary>
        public ScheduledAlertRuleTemplate()
        {
            RequiredDataConnectors = new ChangeTrackingList<AlertRuleTemplateDataSource>();
            Tactics = new ChangeTrackingList<SecurityInsightsAttackTactic>();
            Techniques = new ChangeTrackingList<string>();
            SubTechniques = new ChangeTrackingList<string>();
            CustomDetails = new ChangeTrackingDictionary<string, string>();
            EntityMappings = new ChangeTrackingList<SecurityInsightsAlertRuleEntityMapping>();
            SentinelEntitiesMappings = new ChangeTrackingList<SentinelEntityMapping>();
            Kind = AlertRuleKind.Scheduled;
        }

        /// <summary> Initializes a new instance of <see cref="ScheduledAlertRuleTemplate"/>. </summary>
        /// <param name="id"> The id. </param>
        /// <param name="name"> The name. </param>
        /// <param name="resourceType"> The resourceType. </param>
        /// <param name="systemData"> The systemData. </param>
        /// <param name="kind"> The kind of the alert rule. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        /// <param name="alertRulesCreatedByTemplateCount"> the number of alert rules that were created by this template. </param>
        /// <param name="createdDateUTC"> The time that this alert rule template has been added. </param>
        /// <param name="lastUpdatedDateUTC"> The time that this alert rule template was last updated. </param>
        /// <param name="description"> The description of the alert rule template. </param>
        /// <param name="displayName"> The display name for alert rule template. </param>
        /// <param name="requiredDataConnectors"> The required data connectors for this template. </param>
        /// <param name="status"> The alert rule template status. </param>
        /// <param name="query"> The query that creates alerts for this rule. </param>
        /// <param name="queryFrequency"> The frequency (in ISO 8601 duration format) for this alert rule to run. </param>
        /// <param name="queryPeriod"> The period (in ISO 8601 duration format) that this alert rule looks at. </param>
        /// <param name="severity"> The severity for alerts created by this alert rule. </param>
        /// <param name="triggerOperator"> The operation against the threshold that triggers alert rule. </param>
        /// <param name="triggerThreshold"> The threshold triggers this alert rule. </param>
        /// <param name="tactics"> The tactics of the alert rule template. </param>
        /// <param name="techniques"> The techniques of the alert rule. </param>
        /// <param name="subTechniques"> The sub-techniques of the alert rule. </param>
        /// <param name="version"> The version of this template - in format &lt;a.b.c&gt;, where all are numbers. For example &lt;1.0.2&gt;. </param>
        /// <param name="eventGroupingSettings"> The event grouping settings. </param>
        /// <param name="customDetails"> Dictionary of string key-value pairs of columns to be attached to the alert. </param>
        /// <param name="entityMappings"> Array of the entity mappings of the alert rule. </param>
        /// <param name="alertDetailsOverride"> The alert details override settings. </param>
        /// <param name="sentinelEntitiesMappings"> Array of the sentinel entity mappings of the alert rule. </param>
        internal ScheduledAlertRuleTemplate(ResourceIdentifier id, string name, ResourceType resourceType, SystemData systemData, AlertRuleKind kind, IDictionary<string, BinaryData> serializedAdditionalRawData, int? alertRulesCreatedByTemplateCount, DateTimeOffset? createdDateUTC, DateTimeOffset? lastUpdatedDateUTC, string description, string displayName, IList<AlertRuleTemplateDataSource> requiredDataConnectors, SecurityInsightsAlertRuleTemplateStatus? status, string query, TimeSpan? queryFrequency, TimeSpan? queryPeriod, SecurityInsightsAlertSeverity? severity, SecurityInsightsAlertRuleTriggerOperator? triggerOperator, int? triggerThreshold, IList<SecurityInsightsAttackTactic> tactics, IList<string> techniques, IList<string> subTechniques, string version, EventGroupingSettings eventGroupingSettings, IDictionary<string, string> customDetails, IList<SecurityInsightsAlertRuleEntityMapping> entityMappings, SecurityInsightsAlertDetailsOverride alertDetailsOverride, IList<SentinelEntityMapping> sentinelEntitiesMappings) : base(id, name, resourceType, systemData, kind, serializedAdditionalRawData)
        {
            AlertRulesCreatedByTemplateCount = alertRulesCreatedByTemplateCount;
            CreatedDateUTC = createdDateUTC;
            LastUpdatedDateUTC = lastUpdatedDateUTC;
            Description = description;
            DisplayName = displayName;
            RequiredDataConnectors = requiredDataConnectors;
            Status = status;
            Query = query;
            QueryFrequency = queryFrequency;
            QueryPeriod = queryPeriod;
            Severity = severity;
            TriggerOperator = triggerOperator;
            TriggerThreshold = triggerThreshold;
            Tactics = tactics;
            Techniques = techniques;
            SubTechniques = subTechniques;
            Version = version;
            EventGroupingSettings = eventGroupingSettings;
            CustomDetails = customDetails;
            EntityMappings = entityMappings;
            AlertDetailsOverride = alertDetailsOverride;
            SentinelEntitiesMappings = sentinelEntitiesMappings;
            Kind = kind;
        }

        /// <summary> the number of alert rules that were created by this template. </summary>
        [WirePath("properties.alertRulesCreatedByTemplateCount")]
        public int? AlertRulesCreatedByTemplateCount { get; set; }
        /// <summary> The time that this alert rule template has been added. </summary>
        [WirePath("properties.createdDateUTC")]
        public DateTimeOffset? CreatedDateUTC { get; }
        /// <summary> The time that this alert rule template was last updated. </summary>
        [WirePath("properties.lastUpdatedDateUTC")]
        public DateTimeOffset? LastUpdatedDateUTC { get; }
        /// <summary> The description of the alert rule template. </summary>
        [WirePath("properties.description")]
        public string Description { get; set; }
        /// <summary> The display name for alert rule template. </summary>
        [WirePath("properties.displayName")]
        public string DisplayName { get; set; }
        /// <summary> The required data connectors for this template. </summary>
        [WirePath("properties.requiredDataConnectors")]
        public IList<AlertRuleTemplateDataSource> RequiredDataConnectors { get; }
        /// <summary> The alert rule template status. </summary>
        [WirePath("properties.status")]
        public SecurityInsightsAlertRuleTemplateStatus? Status { get; set; }
        /// <summary> The query that creates alerts for this rule. </summary>
        [WirePath("properties.query")]
        public string Query { get; set; }
        /// <summary> The frequency (in ISO 8601 duration format) for this alert rule to run. </summary>
        [WirePath("properties.queryFrequency")]
        public TimeSpan? QueryFrequency { get; set; }
        /// <summary> The period (in ISO 8601 duration format) that this alert rule looks at. </summary>
        [WirePath("properties.queryPeriod")]
        public TimeSpan? QueryPeriod { get; set; }
        /// <summary> The severity for alerts created by this alert rule. </summary>
        [WirePath("properties.severity")]
        public SecurityInsightsAlertSeverity? Severity { get; set; }
        /// <summary> The operation against the threshold that triggers alert rule. </summary>
        [WirePath("properties.triggerOperator")]
        public SecurityInsightsAlertRuleTriggerOperator? TriggerOperator { get; set; }
        /// <summary> The threshold triggers this alert rule. </summary>
        [WirePath("properties.triggerThreshold")]
        public int? TriggerThreshold { get; set; }
        /// <summary> The tactics of the alert rule template. </summary>
        [WirePath("properties.tactics")]
        public IList<SecurityInsightsAttackTactic> Tactics { get; }
        /// <summary> The techniques of the alert rule. </summary>
        [WirePath("properties.techniques")]
        public IList<string> Techniques { get; }
        /// <summary> The sub-techniques of the alert rule. </summary>
        [WirePath("properties.subTechniques")]
        public IList<string> SubTechniques { get; }
        /// <summary> The version of this template - in format &lt;a.b.c&gt;, where all are numbers. For example &lt;1.0.2&gt;. </summary>
        [WirePath("properties.version")]
        public string Version { get; set; }
        /// <summary> The event grouping settings. </summary>
        internal EventGroupingSettings EventGroupingSettings { get; set; }
        /// <summary> The event grouping aggregation kinds. </summary>
        [WirePath("properties.eventGroupingSettings.aggregationKind")]
        public EventGroupingAggregationKind? EventGroupingAggregationKind
        {
            get => EventGroupingSettings is null ? default : EventGroupingSettings.AggregationKind;
            set
            {
                if (EventGroupingSettings is null)
                    EventGroupingSettings = new EventGroupingSettings();
                EventGroupingSettings.AggregationKind = value;
            }
        }

        /// <summary> Dictionary of string key-value pairs of columns to be attached to the alert. </summary>
        [WirePath("properties.customDetails")]
        public IDictionary<string, string> CustomDetails { get; }
        /// <summary> Array of the entity mappings of the alert rule. </summary>
        [WirePath("properties.entityMappings")]
        public IList<SecurityInsightsAlertRuleEntityMapping> EntityMappings { get; }
        /// <summary> The alert details override settings. </summary>
        [WirePath("properties.alertDetailsOverride")]
        public SecurityInsightsAlertDetailsOverride AlertDetailsOverride { get; set; }
        /// <summary> Array of the sentinel entity mappings of the alert rule. </summary>
        [WirePath("properties.sentinelEntitiesMappings")]
        public IList<SentinelEntityMapping> SentinelEntitiesMappings { get; }
    }
}

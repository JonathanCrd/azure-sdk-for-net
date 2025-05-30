// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// <auto-generated/>

#nullable disable

using System;
using System.Collections.Generic;
using Azure.ResourceManager.Resources.Models;

namespace Azure.ResourceManager.DnsResolver.Models
{
    /// <summary> Describes a DNS security rule for PATCH operation. </summary>
    public partial class DnsSecurityRulePatch
    {
        /// <summary>
        /// Keeps track of any properties unknown to the library.
        /// <para>
        /// To assign an object to the value of this property use <see cref="BinaryData.FromObjectAsJson{T}(T, System.Text.Json.JsonSerializerOptions?)"/>.
        /// </para>
        /// <para>
        /// To assign an already formatted json string to this property use <see cref="BinaryData.FromString(string)"/>.
        /// </para>
        /// <para>
        /// Examples:
        /// <list type="bullet">
        /// <item>
        /// <term>BinaryData.FromObjectAsJson("foo")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("\"foo\"")</term>
        /// <description>Creates a payload of "foo".</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromObjectAsJson(new { key = "value" })</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// <item>
        /// <term>BinaryData.FromString("{\"key\": \"value\"}")</term>
        /// <description>Creates a payload of { "key": "value" }.</description>
        /// </item>
        /// </list>
        /// </para>
        /// </summary>
        private IDictionary<string, BinaryData> _serializedAdditionalRawData;

        /// <summary> Initializes a new instance of <see cref="DnsSecurityRulePatch"/>. </summary>
        public DnsSecurityRulePatch()
        {
            Tags = new ChangeTrackingDictionary<string, string>();
            DnsResolverDomainLists = new ChangeTrackingList<WritableSubResource>();
        }

        /// <summary> Initializes a new instance of <see cref="DnsSecurityRulePatch"/>. </summary>
        /// <param name="tags"> Tags for DNS security rule. </param>
        /// <param name="action"> The action to take on DNS requests that match the DNS security rule. </param>
        /// <param name="dnsResolverDomainLists"> DNS resolver policy domains lists that the DNS security rule applies to. </param>
        /// <param name="dnsSecurityRuleState"> The state of DNS security rule. </param>
        /// <param name="priority"> The priority of the DNS security rule. </param>
        /// <param name="serializedAdditionalRawData"> Keeps track of any properties unknown to the library. </param>
        internal DnsSecurityRulePatch(IDictionary<string, string> tags, DnsSecurityRuleAction action, IList<WritableSubResource> dnsResolverDomainLists, DnsSecurityRuleState? dnsSecurityRuleState, int? priority, IDictionary<string, BinaryData> serializedAdditionalRawData)
        {
            Tags = tags;
            Action = action;
            DnsResolverDomainLists = dnsResolverDomainLists;
            DnsSecurityRuleState = dnsSecurityRuleState;
            Priority = priority;
            _serializedAdditionalRawData = serializedAdditionalRawData;
        }

        /// <summary> Tags for DNS security rule. </summary>
        public IDictionary<string, string> Tags { get; }
        /// <summary> The action to take on DNS requests that match the DNS security rule. </summary>
        internal DnsSecurityRuleAction Action { get; set; }
        /// <summary> The type of action to take. </summary>
        public DnsSecurityRuleActionType? ActionType
        {
            get => Action is null ? default : Action.ActionType;
            set
            {
                if (Action is null)
                    Action = new DnsSecurityRuleAction();
                Action.ActionType = value;
            }
        }

        /// <summary> DNS resolver policy domains lists that the DNS security rule applies to. </summary>
        public IList<WritableSubResource> DnsResolverDomainLists { get; }
        /// <summary> The state of DNS security rule. </summary>
        public DnsSecurityRuleState? DnsSecurityRuleState { get; set; }
        /// <summary> The priority of the DNS security rule. </summary>
        public int? Priority { get; set; }
    }
}

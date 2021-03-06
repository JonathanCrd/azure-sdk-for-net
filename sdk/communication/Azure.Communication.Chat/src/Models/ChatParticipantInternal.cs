// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure.Core;

namespace Azure.Communication.Chat
{
    [CodeGenModel("ChatParticipant")]
    internal partial class ChatParticipantInternal
    {
        internal ChatParticipant ToChatParticipant()
            => new ChatParticipant(this);
    }
}

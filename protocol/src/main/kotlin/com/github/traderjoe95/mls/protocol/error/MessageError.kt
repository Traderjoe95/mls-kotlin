package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType

sealed interface MessageSenderError : PrivateMessageSenderError, PublicMessageSenderError {
  data class InvalidSenderType(val senderType: SenderType, val reason: String) : MessageSenderError
}

sealed interface MessageRecipientError : PrivateMessageRecipientError, PublicMessageRecipientError

sealed interface MessageError : MessageSenderError, MessageRecipientError, PrivateMessageError, PublicMessageError

sealed interface ProcessMessageError {
  data object MustUseCachedStateForOwnCommit : ProcessMessageError
}

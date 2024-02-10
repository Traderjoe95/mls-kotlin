package com.github.traderjoe95.mls.protocol.error

sealed interface PrivateMessageSenderError : SenderCommitError

sealed interface PrivateMessageRecipientError : RecipientCommitError

sealed interface PrivateMessageError : PrivateMessageSenderError, PrivateMessageRecipientError

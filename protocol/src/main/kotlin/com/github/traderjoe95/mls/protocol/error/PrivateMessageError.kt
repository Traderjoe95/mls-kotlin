package com.github.traderjoe95.mls.protocol.error

sealed interface PrivateMessageSenderError : SenderCommitError, CreateMessageError

sealed interface PrivateMessageRecipientError : RecipientCommitError, ProcessMessageError

sealed interface PrivateMessageError : PrivateMessageSenderError, PrivateMessageRecipientError

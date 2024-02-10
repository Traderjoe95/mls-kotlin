package com.github.traderjoe95.mls.protocol.error

sealed interface PublicMessageSenderError : SenderCommitError, ExternalJoinError

sealed interface PublicMessageRecipientError : RecipientCommitError

sealed interface PublicMessageError : PublicMessageSenderError, PublicMessageRecipientError

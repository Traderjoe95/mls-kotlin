package com.github.traderjoe95.mls.protocol.error

sealed interface PublicMessageSenderError : SenderCommitError, ExternalJoinError, CreateMessageError

sealed interface PublicMessageRecipientError : RecipientCommitError, ProcessMessageError

sealed interface PublicMessageError : PublicMessageSenderError, PublicMessageRecipientError {
  data object ApplicationMessageMustNotBePublic : PublicMessageError
}

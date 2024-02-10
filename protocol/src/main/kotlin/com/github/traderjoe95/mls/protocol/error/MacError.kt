package com.github.traderjoe95.mls.protocol.error

sealed interface MacError : RecipientCommitError, JoinError, MessageRecipientError {
  data object BadMac : MacError
}

package com.github.traderjoe95.mls.protocol.error

sealed interface DecryptError : PrivateMessageRecipientError, WelcomeJoinError {
  data object AeadDecryptionFailed : DecryptError
}

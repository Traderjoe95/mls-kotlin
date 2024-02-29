package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.framing.Sender

sealed interface SignatureError : JoinError, LeafNodeCheckError, MessageRecipientError, KeyPackageValidationError {
  data object BadSignature : SignatureError

  data class SignaturePublicKeyKeyNotFound(val sender: Sender) : SignatureError
}

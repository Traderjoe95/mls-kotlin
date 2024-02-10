package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.framing.Sender

sealed interface SignatureError : JoinError, LeafNodeCheckError, MessageRecipientError {
  data object BadSignature : SignatureError

  data class VerificationKeyNotFound(val sender: Sender) : SignatureError
}

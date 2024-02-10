package com.github.traderjoe95.mls.protocol.error

sealed interface RatchetError : PrivateMessageError {
  data class GenerationGone(val ratchetType: String, val generation: UInt) : RatchetError

  data class StepTooLarge(val ratchetType: String, val generation: UInt) : RatchetError
}

package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId

sealed interface ExternalPskError : PskError {
  data class UnknownExternalPsk(val id: ByteArray) : ExternalPskError
}

sealed interface ResumptionPskError : PskError

sealed interface PskError : InvalidCommit, WelcomeJoinError, PreSharedKeyValidationError {
  data class BadPskNonce(val pskId: PreSharedKeyId, val expected: UInt, val length: UInt) : PskError

  data class InvalidPskUsage(val pskId: ResumptionPskId) : PskError

  data class PskNotFound(val pskId: PreSharedKeyId) : PskError
}

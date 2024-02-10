package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId

sealed interface ExternalPskError : PskError {
  data class UnknownExternalPsk(val id: ByteArray) : ExternalPskError
}

sealed interface ResumptionPskError : PskError

sealed interface PskError : InvalidCommit, WelcomeJoinError {
  data class BadPskNonce(val pskId: PreSharedKeyId, val expected: UInt, val length: UInt) : PskError

  data class InvalidPskUsage(val pskId: ResumptionPskId) : PskError
}

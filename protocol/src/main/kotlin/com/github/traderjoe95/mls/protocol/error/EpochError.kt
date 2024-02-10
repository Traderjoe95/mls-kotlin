package com.github.traderjoe95.mls.protocol.error

sealed interface EpochError : RatchetError, MessageRecipientError, ResumptionPskError {
  data object FutureEpoch : EpochError

  data object OutdatedEpoch : EpochError
}

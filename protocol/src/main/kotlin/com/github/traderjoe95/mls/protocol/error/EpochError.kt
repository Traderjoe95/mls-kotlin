package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.GroupId

sealed interface HistoryAccessError : MessageRecipientError

sealed interface EpochError : MessageRecipientError, ResumptionPskError, HistoryAccessError {
  data class FutureEpoch(val groupId: GroupId, val epoch: ULong, val currentEpoch: ULong) : EpochError

  data class EpochNotAvailable(val groupId: GroupId, val epoch: ULong) : EpochError
}

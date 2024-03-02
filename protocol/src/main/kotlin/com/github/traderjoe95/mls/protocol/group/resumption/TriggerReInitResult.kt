package com.github.traderjoe95.mls.protocol.group.resumption

import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.message.MlsCommitMessage

data class TriggerReInitResult(
  val suspendedGroup: GroupState.Suspended,
  val commit: MlsCommitMessage,
)

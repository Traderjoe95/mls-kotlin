package com.github.traderjoe95.mls.protocol.group.resumption

import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.PrepareCommitResult

data class BranchResult(
  val newGroup: GroupState,
  val welcomeMessages: List<PrepareCommitResult.WelcomeMessage>,
)

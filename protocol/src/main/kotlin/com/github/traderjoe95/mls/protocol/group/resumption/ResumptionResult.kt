package com.github.traderjoe95.mls.protocol.group.resumption

import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.WelcomeMessages

data class ResumptionResult(
  val newGroup: GroupState.Active,
  val welcomeMessages: WelcomeMessages,
)

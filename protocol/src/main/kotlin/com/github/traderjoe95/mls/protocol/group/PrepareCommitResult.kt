package com.github.traderjoe95.mls.protocol.group

import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome

data class PrepareCommitResult(
  val newGroupState: GroupState,
  val commit: MlsMessage<GroupMessage<*>>,
  val welcomeMessages: List<WelcomeMessage>,
) {
  data class WelcomeMessage(
    val welcome: MlsMessage<Welcome>,
    val to: List<KeyPackage>,
  )
}

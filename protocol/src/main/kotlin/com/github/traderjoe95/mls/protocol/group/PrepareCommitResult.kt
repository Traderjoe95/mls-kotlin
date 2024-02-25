package com.github.traderjoe95.mls.protocol.group

import com.github.traderjoe95.mls.protocol.message.GroupMessage
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.Welcome

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

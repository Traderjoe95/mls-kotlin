package com.github.traderjoe95.mls.protocol.group

import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsCommitMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.Welcome

typealias WelcomeMessages = List<PrepareCommitResult.WelcomeMessage>

data class PrepareCommitResult(
  val newGroupState: GroupState,
  val commit: MlsCommitMessage,
  val welcomeMessages: WelcomeMessages,
) {
  data class WelcomeMessage(
    val welcome: MlsMessage<Welcome>,
    val to: List<KeyPackage>,
  )
}

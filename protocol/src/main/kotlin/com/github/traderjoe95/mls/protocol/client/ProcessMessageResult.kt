package com.github.traderjoe95.mls.protocol.client

import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent

sealed interface ProcessMessageResult<out Identity : Any> {
  data class WelcomeMessageReceived(
    val welcome: Welcome,
  ) : ProcessMessageResult<Nothing>

  data class GroupInfoMessageReceived(
    val groupInfo: GroupInfo,
  ) : ProcessMessageResult<Nothing>

  data class KeyPackageMessageReceived(
    val keyPackage: KeyPackage,
  ) : ProcessMessageResult<Nothing>

  data class ApplicationMessageReceived(
    val groupId: GroupId,
    val applicationData: AuthenticatedContent<ApplicationData>,
  ) : ProcessMessageResult<Nothing>

  data class HandshakeMessageReceived<out Identity : Any>(
    val groupId: GroupId,
    val result: ProcessHandshakeResult<Identity>,
  ) : ProcessMessageResult<Identity>
}

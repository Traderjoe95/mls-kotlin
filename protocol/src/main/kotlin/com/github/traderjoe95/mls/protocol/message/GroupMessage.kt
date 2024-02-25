package com.github.traderjoe95.mls.protocol.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType

sealed interface GroupMessage<RecipientError> : Message {
  val groupId: GroupId
  val epoch: ULong
  val contentType: ContentType

  context(Raise<RecipientError>)
  suspend fun unprotect(groupState: GroupState.Active): AuthenticatedContent<*>
}

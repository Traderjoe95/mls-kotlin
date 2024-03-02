package com.github.traderjoe95.mls.protocol.message

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.error.ProcessMessageError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType

sealed interface GroupMessage<out C : Content<C>> : Message {
  val groupId: GroupId
  val epoch: ULong
  val contentType: ContentType<C>

  suspend fun unprotect(groupState: GroupState.Active): Either<ProcessMessageError, AuthenticatedContent<C>>
}

package com.github.traderjoe95.mls.protocol.types.framing.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import de.traderjoe.ulid.ULID

interface GroupMessage<RecipientError> : Message {
  val groupId: ULID
  val epoch: ULong
  val contentType: ContentType

  context(GroupState, Raise<RecipientError>)
  suspend fun getAuthenticatedContent(): AuthenticatedContent<*>
}

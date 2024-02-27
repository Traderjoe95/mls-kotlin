package com.github.traderjoe95.mls.protocol.types.framing.enums

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit as CommitContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal as ProposalContent

sealed class ContentType<out C : Content<C>>(
  ord: UInt,
  override val isValid: Boolean = true,
) : ProtocolEnum<ContentType<*>> {
  sealed class Handshake<out C : Content.Handshake<C>>(ord: UInt) : ContentType<C>(ord)

  @Deprecated("This reserved value isn't used by the protocol for now")
  data object Reserved : ContentType<Nothing>(0U, false)

  data object Application : ContentType<ApplicationData>(1U)

  data object Proposal : Handshake<ProposalContent>(2U)

  data object Commit : Handshake<CommitContent>(3U)

  companion object {
    @Suppress("DEPRECATION")
    val T: EnumT<ContentType<*>> by lazy {
      // Funny thing: This needs to be lazy, because otherwise the initialization happens in the wrong order; this leads
      // to Proposal being uninitialized/null
      throwAnyError { enum(Reserved, Application, Proposal, Commit, upperBound = 0xFFU) }
    }
  }

  override val ord: UIntRange = ord..ord
  override val name: String
    get() = toString()

  override fun compareTo(other: ContentType<*>): Int = ord.first.compareTo(other.ord.first)
}

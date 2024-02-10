package com.github.traderjoe95.mls.protocol.types.framing.enums

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError

enum class SenderType(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<SenderType> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0U, false),

  Member(1U),
  External(2U),
  NewMemberProposal(3U),
  NewMemberCommit(4U),
  ;

  override val ord: UIntRange = ord..ord

  companion object {
    val T: EnumT<SenderType> = throwAnyError { enum(upperBound = 0xFFU) }
  }
}

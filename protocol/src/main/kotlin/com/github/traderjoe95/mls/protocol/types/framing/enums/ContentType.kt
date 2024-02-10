package com.github.traderjoe95.mls.protocol.types.framing.enums

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError

enum class ContentType(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<ContentType> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0U, false),

  Application(1U),
  Proposal(2U),
  Commit(3U),

  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  UPPER_(0xFFU, false),
  ;

  override val ord: UIntRange = ord..ord

  companion object {
    val T: EnumT<ContentType> = throwAnyError { enum() }
  }
}

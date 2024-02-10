package com.github.traderjoe95.mls.protocol.types.framing.enums

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError

enum class ProtocolVersion(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<ProtocolVersion> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0U, false),

  // RFC 9420
  MLS_1_0(1U),

  // Upper bound to force field width
  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  UPPER_(0xFFFFU, false),
  ;

  override val ord: UIntRange = ord..ord

  companion object {
    val T: EnumT<ProtocolVersion> = throwAnyError { enum() }
  }
}

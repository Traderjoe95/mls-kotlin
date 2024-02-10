package com.github.traderjoe95.mls.protocol.types.framing.enums

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError

enum class WireFormat(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<WireFormat> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0x0000U, false),

  MlsPublicMessage(0x0001U),
  MlsPrivateMessage(0x0002U),
  MlsWelcome(0x0003U),
  MlsGroupInfo(0x0004U),
  MlsKeyPackage(0x0005U),

  // Upper bound to force field width
  @Deprecated("This is technically required, but must not be used", level = DeprecationLevel.ERROR)
  UPPER_(0xFFFFU, false),
  ;

  override val ord: UIntRange = ord..ord

  companion object {
    val T: EnumT<WireFormat> = throwAnyError { enum() }
  }
}

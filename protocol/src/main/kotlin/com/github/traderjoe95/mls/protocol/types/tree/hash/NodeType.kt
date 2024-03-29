package com.github.traderjoe95.mls.protocol.types.tree.hash

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError

enum class NodeType(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<NodeType> {
  @Deprecated("This reserved value isn't used by the protocol for now", level = DeprecationLevel.ERROR)
  Reserved(0U, false),

  Leaf(1U),
  Parent(2U),
  ;

  override val ord: UIntRange = ord..ord

  companion object {
    val T: EnumT<NodeType> = throwAnyError { enum(upperBound = 0xFFU) }
  }
}

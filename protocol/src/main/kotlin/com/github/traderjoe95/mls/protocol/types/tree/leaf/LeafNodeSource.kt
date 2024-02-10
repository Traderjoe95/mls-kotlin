package com.github.traderjoe95.mls.protocol.types.tree.leaf

import com.github.traderjoe95.mls.codec.type.EnumT
import com.github.traderjoe95.mls.codec.type.ProtocolEnum
import com.github.traderjoe95.mls.codec.type.enum
import com.github.traderjoe95.mls.codec.util.throwAnyError

sealed class LeafNodeSource(ord: UInt, override val isValid: Boolean = true) : ProtocolEnum<LeafNodeSource> {
  override val name: String
    get() = toString()
  override val ord: UIntRange = ord..ord

  override fun compareTo(other: LeafNodeSource): Int = ord.first.compareTo(other.ord.first)

  companion object {
    @Suppress("DEPRECATION")
    val T: EnumT<LeafNodeSource> =
      throwAnyError {
        enum(
          // Reserved
          Reserved,
          // RFC-9420
          KeyPackage,
          Update,
          Commit,
          upperBound = 0xFFU,
        )
      }
  }

  @Deprecated("This reserved value isn't used by the protocol for now")
  data object Reserved : LeafNodeSource(0U, false)

  data object KeyPackage : LeafNodeSource(1U)

  data object Update : LeafNodeSource(2U)

  data object Commit : LeafNodeSource(3U)
}

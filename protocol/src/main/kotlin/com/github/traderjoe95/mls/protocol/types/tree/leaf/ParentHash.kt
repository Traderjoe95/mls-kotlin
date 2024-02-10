package com.github.traderjoe95.mls.protocol.types.tree.leaf

import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque

data class ParentHash(val value: ByteArray) : LeafNodeInfo {
  companion object {
    val T: DataType<ParentHash> = opaque[V].derive({ ParentHash(it) }, { it.value })

    val empty: ParentHash
      get() = ParentHash(byteArrayOf())

    val ByteArray.asParentHash: ParentHash
      get() = ParentHash(this)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as ParentHash

    return value.contentEquals(other.value)
  }

  override fun hashCode(): Int {
    return value.contentHashCode()
  }
}

package com.github.traderjoe95.mls.protocol.types.tree.leaf

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque

@JvmInline
value class ParentHash(val value: ByteArray) : LeafNodeInfo {
  companion object : Encodable<ParentHash> {
    override val dataT: DataType<ParentHash> = opaque[V].derive({ ParentHash(it) }, { it.value })

    val empty: ParentHash
      get() = ParentHash(byteArrayOf())

    val ByteArray.asParentHash: ParentHash
      get() = ParentHash(this)

    fun ParentHash?.eqNullable(other: ParentHash?): Boolean =
      when {
        this == null && other == null -> true
        this != null && other != null -> eq(other)
        else -> false
      }
  }

  val hashCode: Int
    get() = value.contentHashCode()

  fun eq(other: ParentHash): Boolean = value.contentEquals(other.value)
}

package com.github.traderjoe95.mls.protocol.types.tree.leaf

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.protocol.types.RefinedBytes

@JvmInline
value class ParentHash(override val bytes: ByteArray) : LeafNodeInfo, RefinedBytes<ParentHash> {
  companion object : Encodable<ParentHash> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<ParentHash> = opaque[V].derive({ ParentHash(it) }, { it.bytes })

    val empty: ParentHash
      get() = ParentHash(byteArrayOf())

    val ByteArray.asParentHash: ParentHash
      get() = ParentHash(this)
  }
}

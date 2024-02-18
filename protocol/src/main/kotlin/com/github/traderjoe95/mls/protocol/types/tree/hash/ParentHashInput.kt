package com.github.traderjoe95.mls.protocol.types.tree.hash

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash

data class ParentHashInput(
  val encryptionKey: HpkePublicKey,
  val parentHash: ParentHash,
  val originalSiblingTreeHash: ByteArray,
) : Struct3T.Shape<HpkePublicKey, ParentHash, ByteArray> {
  companion object : Encodable<ParentHashInput> {
    override val dataT: DataType<ParentHashInput> =
      struct("ParentHashInput") {
        it.field("encryption_key", HpkePublicKey.dataT)
          .field("parent_hash", ParentHash.dataT)
          .field("original_sibling_tree_hash", opaque[V])
      }.lift(::ParentHashInput)
  }
}

package com.github.traderjoe95.mls.protocol.types.tree

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash

data class ParentNode(
  override val encryptionKey: HpkePublicKey,
  override val parentHash: ParentHash,
  val unmergedLeaves: List<LeafIndex>,
) : Struct3T.Shape<HpkePublicKey, ParentHash, List<LeafIndex>>, Node {
  override fun withParentHash(parentHash: ParentHash): Node = copy(parentHash = parentHash)

  companion object : Encodable<ParentNode> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<ParentNode> =
      struct("ParentNode") {
        it.field("encryption_key", HpkePublicKey.T)
          .field("parent_hash", ParentHash.T)
          .field("unmerged_leaves", LeafIndex.T[V])
      }.lift(::ParentNode)

    fun new(encryptionKey: HpkePublicKey): ParentNode = ParentNode(encryptionKey, ParentHash.empty, listOf())
  }
}

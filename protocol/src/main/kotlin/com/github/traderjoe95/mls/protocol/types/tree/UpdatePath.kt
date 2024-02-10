package com.github.traderjoe95.mls.protocol.types.tree

import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource

data class UpdatePathNode(
  val encryptionKey: HpkePublicKey,
  val encryptedPathSecret: List<HpkeCiphertext>,
) : Struct2T.Shape<HpkePublicKey, List<HpkeCiphertext>> {
  companion object {
    val T: DataType<UpdatePathNode> =
      struct("UpdatePathNode") {
        it.field("encryption_key", HpkePublicKey.T)
          .field("encrypted_path_secret", HpkeCiphertext.T[V])
      }.lift(::UpdatePathNode)
  }
}

data class UpdatePath(
  val leafNode: CommitLeafNode,
  val nodes: List<UpdatePathNode>,
) : Struct2T.Shape<CommitLeafNode, List<UpdatePathNode>> {
  val size: UInt
    get() = nodes.uSize

  companion object {
    val T: DataType<UpdatePath> =
      struct("UpdatePath") {
        it.field("leaf_node", LeafNode.t(LeafNodeSource.Commit))
          .field("nodes", UpdatePathNode.T[V])
      }.lift(::UpdatePath)
  }
}

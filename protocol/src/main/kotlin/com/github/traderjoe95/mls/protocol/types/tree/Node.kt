package com.github.traderjoe95.mls.protocol.types.tree

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.tree.hash.NodeType
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash

sealed interface Node {
  val encryptionKey: HpkePublicKey
  val parentHash: ParentHash?

  fun withParentHash(parentHash: ParentHash): Node

  val asParent: ParentNode
    get() = this as ParentNode

  val asLeaf: LeafNode<*>
    get() = this as LeafNode<*>

  companion object : Encodable<Node> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<Node> =
      struct("Node") {
        it.field("node_type", NodeType.T)
          .select<Node, _>(NodeType.T, "node_type") {
            case(NodeType.Leaf).then(LeafNode.T, "leaf_node")
              .case(NodeType.Parent).then(ParentNode.T, "parent")
          }
      }.lift({ _, node -> node }) {
        when (it) {
          is ParentNode -> Struct2(NodeType.Parent, it)
          is LeafNode<*> -> Struct2(NodeType.Leaf, it)
        }
      }
  }
}

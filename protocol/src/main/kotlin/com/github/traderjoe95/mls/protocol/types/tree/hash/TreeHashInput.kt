package com.github.traderjoe95.mls.protocol.types.tree.hash

import arrow.core.Option
import arrow.core.toOption
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode

data class TreeHashInput(
  val nodeType: NodeType,
  val node: NodeHashInput,
) : Struct2T.Shape<NodeType, NodeHashInput> {
  companion object : Encodable<TreeHashInput> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<TreeHashInput> =
      throwAnyError {
        struct("TreeHashInput") {
          it.field("node_type", NodeType.T)
            .select<NodeHashInput, _>(NodeType.T, "node_type") {
              case(NodeType.Leaf).then(LeafNodeHashInput.T, "leaf_node")
                .case(NodeType.Parent).then(ParentNodeHashInput.T, "parent_node")
            }
        }.lift(::TreeHashInput)
      }

    fun forLeaf(
      leafIndex: LeafIndex,
      leafNode: LeafNode<*>?,
    ): TreeHashInput = TreeHashInput(NodeType.Leaf, LeafNodeHashInput(leafIndex, leafNode.toOption()))

    fun forParent(
      parentNode: ParentNode?,
      leftHash: ByteArray,
      rightHash: ByteArray,
    ): TreeHashInput = TreeHashInput(NodeType.Parent, ParentNodeHashInput(parentNode.toOption(), leftHash, rightHash))
  }
}

sealed interface NodeHashInput

data class LeafNodeHashInput(
  val leafIndex: LeafIndex,
  val leafNode: Option<LeafNode<*>>,
) : NodeHashInput, Struct2T.Shape<LeafIndex, Option<LeafNode<*>>> {
  companion object : Encodable<LeafNodeHashInput> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<LeafNodeHashInput> =
      struct("LeafNodeHashInput") {
        it.field("leaf_index", LeafIndex.T)
          .field("leaf_node", optional[LeafNode.T])
      }.lift(::LeafNodeHashInput)
  }
}

data class ParentNodeHashInput(
  val parentNode: Option<ParentNode>,
  val leftHash: ByteArray,
  val rightHash: ByteArray,
) : NodeHashInput, Struct3T.Shape<Option<ParentNode>, ByteArray, ByteArray> {
  companion object : Encodable<ParentNodeHashInput> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<ParentNodeHashInput> =
      struct("LeafNodeHashInput") {
        it.field("parent_node", optional[ParentNode.T])
          .field("left_hash", opaque[V])
          .field("right_hash", opaque[V])
      }.lift(::ParentNodeHashInput)
  }
}

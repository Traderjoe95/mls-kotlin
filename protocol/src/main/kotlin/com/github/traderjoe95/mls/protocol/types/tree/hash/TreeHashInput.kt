package com.github.traderjoe95.mls.protocol.types.tree.hash

import arrow.core.Option
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.tree.LeafNodeRecord
import com.github.traderjoe95.mls.protocol.tree.ParentNodeRecord
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode

data class TreeHashInput(
  val nodeType: NodeType,
  val node: NodeHashInput,
) : Struct2T.Shape<NodeType, NodeHashInput> {
  companion object {
    val T: DataType<TreeHashInput> =
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
      leafIndex: UInt,
      leafNode: LeafNodeRecord?,
    ): TreeHashInput = TreeHashInput(NodeType.Leaf, LeafNodeHashInput(leafIndex, leafNode))

    fun forParent(
      parentNode: ParentNodeRecord?,
      leftHash: ByteArray,
      rightHash: ByteArray,
    ): TreeHashInput = TreeHashInput(NodeType.Parent, ParentNodeHashInput(parentNode, leftHash, rightHash))
  }
}

sealed interface NodeHashInput

data class LeafNodeHashInput(
  val leafIndex: UInt,
  val leafNode: Option<LeafNode<*>>,
) : NodeHashInput, Struct2T.Shape<UInt, Option<LeafNode<*>>> {
  constructor(leafIndex: UInt, leafNode: LeafNodeRecord?) : this(leafIndex, Option.fromNullable(leafNode?.node))

  companion object {
    val T: DataType<LeafNodeHashInput> =
      struct("LeafNodeHashInput") {
        it.field("leaf_index", uint32.asUInt)
          .field("leaf_node", optional[LeafNode.T])
      }.lift(::LeafNodeHashInput)
  }
}

data class ParentNodeHashInput(
  val parentNode: Option<ParentNode>,
  val leftHash: ByteArray,
  val rightHash: ByteArray,
) : NodeHashInput, Struct3T.Shape<Option<ParentNode>, ByteArray, ByteArray> {
  constructor(parentNode: ParentNodeRecord?, leftHash: ByteArray, rightHash: ByteArray) : this(
    Option.fromNullable(parentNode?.node),
    leftHash,
    rightHash,
  )

  companion object {
    val T: DataType<ParentNodeHashInput> =
      struct("LeafNodeHashInput") {
        it.field("parent_node", optional[ParentNode.T])
          .field("left_hash", opaque[V])
          .field("right_hash", opaque[V])
      }.lift(::ParentNodeHashInput)
  }
}

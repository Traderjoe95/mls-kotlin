package com.github.traderjoe95.mls.protocol.tree

import arrow.core.Option
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.UpdateLeafNode
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.protocol.util.log2
import com.github.traderjoe95.mls.protocol.util.set
import com.github.traderjoe95.mls.protocol.util.shl
import com.github.traderjoe95.mls.protocol.util.sliceArray
import com.github.traderjoe95.mls.protocol.util.uSize

@JvmInline
value class RatchetTree private constructor(private val nodes: Array<Node?>) {
  init {
    check(nodes.isEmpty() || (nodes.size - 1) % 2 == 0)
  }

  val size: UInt
    get() = nodes.uSize
  inline val root: NodeIndex
    get() = NodeIndex((1U shl log2(size)) - 1U)

  internal inline val leafNodeIndices: NodeProgression
    get() = NodeIndex(0U)..<size step 2
  internal inline val parentNodeIndices: NodeProgression
    get() = NodeIndex(1U)..<size step 2

  @Suppress("UNCHECKED_CAST", "kotlin:S6531")
  val leaves: List<LeafNode<*>?>
    get() = this[leafNodeIndices] as List<LeafNode<*>?>

  val firstBlankLeaf: LeafIndex?
    get() = leafNodeIndices.find { it.isBlank }?.leafIndex

  fun insert(newLeaf: LeafNode<*>): Pair<RatchetTree, LeafIndex> =
    firstBlankLeaf
      ?.let { newLeaf.insertAt(it.nodeIndex) }
      ?: extend().insert(newLeaf)

  private fun LeafNode<*>.insertAt(nodeIdx: NodeIndex): Pair<RatchetTree, LeafIndex> {
    val leafIdx = nodeIdx.leafIndex

    val updatedTree = this@RatchetTree.copy().apply { this[nodeIdx] = this@insertAt }

    directPath(nodeIdx).dropLast(1).forEach { intermediateNode ->
      updatedTree[intermediateNode] =
        updatedTree[intermediateNode]?.asParent?.run { copy(unmergedLeaves = unmergedLeaves + leafIdx) }
    }

    return updatedTree to leafIdx
  }

  operator fun minus(leafIndex: LeafIndex): RatchetTree =
    copy().apply { this[leafIndex] = null }
      .blank(directPath(leafIndex).dropLast(1))
      .truncateIfRequired()

  fun update(
    leafIndex: LeafIndex,
    leafNode: UpdateLeafNode,
  ): RatchetTree =
    copy().apply { this[leafIndex] = leafNode }
      .blank(directPath(leafIndex).dropLast(1))

  val TreeIndex.filteredParent: NodeIndex
    get() = filteredDirectPath(this).firstOrNull() ?: root

  val TreeIndex.isBlank: Boolean
    get() = nodeIndex >= nodes.size.toUInt() || nodes[nodeIndex.value] == null

  operator fun get(nodeIndex: TreeIndex): Node? = nodes[nodeIndex.nodeIndex.value]

  operator fun get(indices: Iterable<TreeIndex>): List<Node?> = nodes[indices.map { it.nodeIndex.value }]

  operator fun set(
    nodeIndex: TreeIndex,
    node: Node?,
  ) {
    nodes[nodeIndex.nodeIndex.value] = node
  }

  private val leftSubtree: RatchetTree
    get() = RatchetTree(nodes.sliceArray(0U..<root.value))

  private fun extend(): RatchetTree {
    return RatchetTree(
      Array<Node?>(nodes.size * 2 + 1) { null }.also { nodes.copyInto(it, 0) },
    )
  }

  private fun truncateIfRequired(): RatchetTree {
    var result = this

    while (
      ((result.root + 1U)..<result.size).all {
        with(result) { it.isBlank }
      }
    ) {
      result = leftSubtree
    }

    return result
  }

  internal fun copy(): RatchetTree = RatchetTree(nodes.copyOf())

  companion object : Encodable<RatchetTree> {
    override val dataT: DataType<RatchetTree> =
      optional[Node.dataT][V].derive(
        { nodes ->
          if (nodes.last().isNone()) {
            raise(DecoderError.UnexpectedError("Last node of an encoded ratchet tree must not be blank"))
          }

          val d = log2(nodes.uSize)
          val synthesizeBlankNodes = (1U shl (d + 1U)) - nodes.uSize - 1U

          RatchetTree(
            nodes.map { it.getOrNull() }.toTypedArray() + Array<Node?>(synthesizeBlankNodes.toInt()) { null },
          )
        },
        { tree -> tree.nodes.map(Option.Companion::fromNullable).dropLastWhile(Option<Node>::isNone) },
      )

    fun LeafNode<*>.newTree(): RatchetTree = RatchetTree(arrayOf(this))
  }
}

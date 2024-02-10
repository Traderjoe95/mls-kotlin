package com.github.traderjoe95.mls.protocol.tree

import arrow.core.None
import arrow.core.Option
import arrow.core.Some
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.protocol.util.log2
import com.github.traderjoe95.mls.protocol.util.set
import com.github.traderjoe95.mls.protocol.util.shl
import com.github.traderjoe95.mls.protocol.util.shr
import com.github.traderjoe95.mls.protocol.util.sliceArray
import com.github.traderjoe95.mls.protocol.util.uSize

@JvmInline
value class RatchetTree private constructor(private val nodes: Array<NodeRecord<*>?>) {
  init {
    check(nodes.isEmpty() || (nodes.size - 1) % 2 == 0)
  }

  val size: UInt
    get() = nodes.uSize
  inline val root: UInt
    get() = (1U shl log2(size)) - 1U
  internal inline val leafIndices: UIntProgression
    get() = 0U..<nodes.uSize step 2
  internal inline val parentIndices: UIntProgression
    get() = 1U..<size step 2

  @Suppress("UNCHECKED_CAST", "kotlin:S6531")
  val leaves: List<LeafNodeRecord?>
    get() = nodes[leafIndices] as List<LeafNodeRecord?>

  @Suppress("UNCHECKED_CAST", "kotlin:S6531")
  val parents: List<ParentNodeRecord?>
    get() = nodes[parentIndices] as List<ParentNodeRecord?>

  val firstBlankLeaf: UInt?
    get() = leafIndices.find { it.isBlank }

  operator fun plus(newLeaf: LeafNode<*>): RatchetTree = this + LeafNodeRecord(newLeaf to null)

  operator fun plus(newLeaf: LeafNodeRecord): RatchetTree = insert(newLeaf).first

  fun insert(newLeaf: LeafNode<*>): Pair<RatchetTree, UInt> = insert(LeafNodeRecord(newLeaf to null))

  fun insert(newLeaf: LeafNodeRecord): Pair<RatchetTree, UInt> =
    firstBlankLeaf.let { idx ->
      if (idx != null) {
        val leafIdx = idx / 2U

        directPath(idx).dropLast(1).forEach { intermediateNode ->
          this[intermediateNode] =
            this[intermediateNode]?.asParent?.updateNode {
              copy(unmergedLeaves = unmergedLeaves + leafIdx)
            }
        }

        copy().apply { nodes[idx] = newLeaf } to leafIdx
      } else {
        extend().insert(newLeaf)
      }
    }

  operator fun minus(leafIndex: UInt): RatchetTree =
    copy().apply { nodes[leafIndex.leafNodeIndex] = null }
      .blank(directPath(leafIndex.leafNodeIndex).dropLast(1))
      .truncateIfRequired()

  val UInt.level
    get() = generateSequence(0) { it + 1 }.find { (this shr it) and 0x01U == 0U }!!.toUInt()

  val UInt.leafNodeIndex: UInt
    get() = this * 2U

  val UInt.sibling: UInt
    get() =
      parent.let { p ->
        if (this < p) {
          p.rightChild
        } else {
          p.leftChild
        }
      }

  val UInt.parent: UInt
    get() =
      level.let { k ->
        val b = (this shr (k + 1U)) and 0x01U
        (this or (1U shl k)) xor (b shl (k + 1U))
      }
  val UInt.filteredParent: UInt
    get() = filteredDirectPath(this).firstOrNull() ?: 0U
  val UInt.leftChild: UInt
    get() = this xor (0x01U shl (level - 1U))
  val UInt.rightChild: UInt
    get() = this xor (0x03U shl (level - 1U))

  val UInt.isBlank: Boolean
    get() = this >= nodes.size.toUInt() || nodes[this] == null

  operator fun get(nodeIndex: UInt): NodeRecord<*>? = nodes[nodeIndex]

  operator fun get(indices: Iterable<UInt>): List<NodeRecord<*>?> = nodes[indices]

  operator fun set(
    nodeIndex: UInt,
    node: LeafNode<*>,
  ) {
    this[nodeIndex] = LeafNodeRecord(node to null)
  }

  operator fun set(
    nodeIndex: UInt,
    node: ParentNode,
  ) {
    this[nodeIndex] = ParentNodeRecord(node to null)
  }

  operator fun set(
    nodeIndex: UInt,
    node: NodeRecord<*>?,
  ) {
    nodes[nodeIndex] = node
  }

  private val leftSubtree: RatchetTree
    get() = RatchetTree(nodes.sliceArray(0U..<root))

  val UInt.subtree: RatchetTree
    get() = RatchetTree(nodes[subtreeRange].toTypedArray())

  private fun extend(): RatchetTree {
    return RatchetTree(
      Array<NodeRecord<*>?>(nodes.size * 2 + 1) { null }.also { nodes.copyInto(it, 0) },
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

  companion object {
    val T: DataType<RatchetTree> =
      optional[Node.T][V].derive(
        { nodes ->
          if (nodes.last().isNone()) {
            raise(DecoderError.UnexpectedError("Last node of an encoded ratchet tree must not be blank"))
          }

          val d = log2(nodes.uSize)
          val synthesizeBlankNodes = (1U shl (d + 1U)) - nodes.uSize - 1U

          RatchetTree(
            nodes.map {
              when (it) {
                is None -> null
                is Some ->
                  when (val node = it.value) {
                    is ParentNode -> ParentNodeRecord(node to null)
                    is LeafNode<*> -> LeafNodeRecord(node to null)
                  }
              }
            }.toTypedArray() +
              Array<NodeRecord<*>?>(synthesizeBlankNodes.toInt()) { null },
          )
        },
        { tree -> tree.nodes.map { Option.fromNullable(it?.node) }.dropLastWhile { it.isNone() } },
      )

    fun LeafNodeRecord.newTree(): RatchetTree = RatchetTree(arrayOf(this))
  }
}

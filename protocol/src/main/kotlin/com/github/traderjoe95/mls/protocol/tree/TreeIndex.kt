package com.github.traderjoe95.mls.protocol.tree

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.util.log2
import com.github.traderjoe95.mls.protocol.util.shl
import com.github.traderjoe95.mls.protocol.util.shr

fun lowestCommonAncestor(
  node1: TreeIndex,
  node2: TreeIndex,
): NodeIndex {
  var n1 = node1.nodeIndex
  var n2 = node2.nodeIndex

  while (n1.level != n2.level) {
    if (n1.level < n2.level) {
      n1 = n1.parent
    } else {
      n2 = n2.parent
    }
  }

  while (n1 != n2) {
    n1 = n1.parent
    n2 = n2.parent
  }

  return n1
}

sealed interface TreeIndex : Comparable<TreeIndex> {
  val leafIndex: LeafIndex
  val nodeIndex: NodeIndex

  val isLeaf: Boolean

  val level: UInt
  val parent: NodeIndex
  val sibling: NodeIndex

  val subtreeRange: NodeRange

  fun isInSubtreeOf(node: TreeIndex): Boolean = this in node.subtreeRange

  override fun compareTo(other: TreeIndex): Int = nodeIndex.value.compareTo(other.nodeIndex.value)
}

@JvmInline
value class LeafIndex(val value: UInt) : TreeIndex {
  override val leafIndex: LeafIndex
    get() = this
  override val nodeIndex: NodeIndex
    get() = NodeIndex(value * 2U)

  override val isLeaf: Boolean
    get() = true

  override val level: UInt
    get() = 0U

  override val parent: NodeIndex
    get() = if (value % 2U == 0U) nodeIndex + 1U else nodeIndex - 1U

  override val sibling: NodeIndex
    get() = if (value % 2U == 0U) nodeIndex + 2U else nodeIndex - 2U

  override val subtreeRange: NodeRange
    get() = nodeIndex..nodeIndex

  infix fun eq(other: LeafIndex) = value == other.value

  infix fun neq(other: LeafIndex) = value != other.value

  infix fun eq(index: UInt): Boolean = value == index

  infix fun eq(index: Int): Boolean = value == index.toUInt()

  companion object : Encodable<LeafIndex> {
    override val dataT: DataType<LeafIndex> = uint32.asUInt.derive({ LeafIndex(it) }, { it.value })
  }
}

fun Iterable<LeafNode<*>?>.zipWithLeafIndex(): Iterable<Pair<LeafNode<*>?, LeafIndex>> =
  zip(generateSequence(LeafIndex(0U)) { LeafIndex(it.value + 1U) }.asIterable())

fun Sequence<LeafNode<*>?>.zipWithLeafIndex(): Sequence<Pair<LeafNode<*>?, LeafIndex>> =
  zip(generateSequence(LeafIndex(0U)) { LeafIndex(it.value + 1U) })

@JvmInline
value class NodeIndex(val value: UInt) : TreeIndex {
  override val leafIndex: LeafIndex
    get() = if (isLeaf) LeafIndex(value / 2U) else error("This is a parent node")
  override val nodeIndex: NodeIndex
    get() = this
  override val isLeaf: Boolean
    get() = value % 2U == 0U

  val isParent: Boolean
    get() = value % 2U == 1U

  override val level: UInt
    get() = generateSequence(0) { it + 1 }.find { (nodeIndex.value shr it) and 0x01U == 0U }!!.toUInt()

  override val parent: NodeIndex
    get() =
      level.let { k ->
        val b = (nodeIndex.value shr (k + 1U)) and 0x01U
        (nodeIndex or (1U shl k)) xor (b shl (k + 1U))
      }

  override val sibling: NodeIndex
    get() =
      parent.let { p ->
        if (nodeIndex < p) {
          p.rightChild
        } else {
          p.leftChild
        }
      }

  val leftChild: NodeIndex
    get() = this xor (0x01U shl (level - 1U))
  val rightChild: NodeIndex
    get() = this xor (0x03U shl (level - 1U))

  override val subtreeRange: NodeRange
    get() = if (isLeaf) this..this else ((1U shl level) - 1U).let { width -> (nodeIndex - width)..(nodeIndex + width) }

  infix fun or(other: UInt): NodeIndex = NodeIndex(value or other)

  infix fun xor(other: UInt): NodeIndex = NodeIndex(value xor other)

  operator fun compareTo(other: UInt): Int = value.compareTo(other)

  operator fun plus(rhs: UInt): NodeIndex = NodeIndex(value + rhs)

  operator fun minus(rhs: UInt): NodeIndex = NodeIndex(value - rhs)

  operator fun rangeTo(upper: UInt): NodeRange = NodeRange(value..upper)

  operator fun rangeUntil(upper: UInt): NodeRange = NodeRange(value..<upper)

  operator fun rangeTo(upper: NodeIndex): NodeRange = NodeRange(value..upper.value)

  operator fun rangeUntil(upper: NodeIndex): NodeRange = NodeRange(value..<upper.value)

  companion object {
    fun root(nodeCount: UInt): NodeIndex = NodeIndex((1U shl log2(nodeCount)) - 1U)
  }
}

class NodeRange internal constructor(private val indices: UIntRange) :
  NodeProgression(indices),
  ClosedRange<NodeIndex>,
  OpenEndRange<NodeIndex> {
    override val start: NodeIndex
      get() = NodeIndex(indices.first)

    override val endInclusive: NodeIndex
      get() = NodeIndex(indices.last)

    override val endExclusive: NodeIndex
      get() = NodeIndex(indices.last + 1U)

    override fun contains(value: NodeIndex): Boolean = value.value in indices

    operator fun contains(node: TreeIndex): Boolean = node.nodeIndex in this

    override fun isEmpty(): Boolean = indices.isEmpty()

    infix fun step(step: Int): NodeProgression = NodeProgression(indices step step)

    override fun toString(): String = "Node(${first.value})..Node(${last.value})"
  }

open class NodeProgression internal constructor(private val indices: UIntProgression) : Iterable<NodeIndex> {
  val first: NodeIndex
    get() = NodeIndex(indices.first)

  val last: NodeIndex
    get() = NodeIndex(indices.last)

  val step: Int
    get() = indices.step

  override fun iterator(): Iterator<NodeIndex> = indices.asSequence().map(::NodeIndex).iterator()

  override fun toString(): String = "Node(${first.value})..Node(${last.value}) step $step"
}

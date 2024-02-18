package com.github.traderjoe95.mls.protocol.tree

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.util.shl
import com.github.traderjoe95.mls.protocol.util.shr

sealed interface TreeIndex {
  val leafIndex: LeafIndex
  val nodeIndex: NodeIndex

  val isLeaf: Boolean

  val level: UInt
  val parent: NodeIndex
  val sibling: NodeIndex
}

@JvmInline
value class LeafIndex(val value: UInt) : TreeIndex, Comparable<LeafIndex> {
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

  override fun compareTo(other: LeafIndex): Int = value.compareTo(other.value)

  companion object : Encodable<LeafIndex> {
    override val dataT: DataType<LeafIndex> = uint32.asUInt.derive({ LeafIndex(it) }, { it.value })
  }
}

fun Iterable<LeafNode<*>?>.zipWithLeafIndex(): Iterable<Pair<LeafNode<*>?, LeafIndex>> =
  zip(generateSequence(LeafIndex(0U)) { LeafIndex(it.value + 1U) }.asIterable())

@JvmInline
value class NodeIndex(val value: UInt) : TreeIndex, Comparable<NodeIndex> {
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

  infix fun shr(bits: UInt): NodeIndex = NodeIndex(value shr bits)

  infix fun shl(bits: UInt): NodeIndex = NodeIndex(value shl bits)

  infix fun and(other: UInt): NodeIndex = NodeIndex(value and other)

  infix fun or(other: UInt): NodeIndex = NodeIndex(value or other)

  infix fun xor(other: UInt): NodeIndex = NodeIndex(value xor other)

  operator fun compareTo(other: UInt): Int = value.compareTo(other)

  override fun compareTo(other: NodeIndex): Int = value.compareTo(other.value)

  operator fun plus(rhs: UInt): NodeIndex = NodeIndex(value + rhs)

  operator fun minus(rhs: UInt): NodeIndex = NodeIndex(value - rhs)

  operator fun rangeTo(upper: UInt): NodeRange = NodeRange(value..upper)

  operator fun rangeUntil(upper: UInt): NodeRange = NodeRange(value..<upper)

  operator fun rangeTo(upper: NodeIndex): NodeRange = NodeRange(value..upper.value)

  operator fun rangeUntil(upper: NodeIndex): NodeRange = NodeRange(value..<upper.value)
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

    override fun isEmpty(): Boolean = indices.isEmpty()

    infix fun step(step: Int): NodeProgression = NodeProgression(indices step step)
  }

open class NodeProgression internal constructor(private val indices: UIntProgression) : Iterable<NodeIndex> {
  val first: NodeIndex
    get() = NodeIndex(indices.first)

  val last: NodeIndex
    get() = NodeIndex(indices.last)

  val step: Int
    get() = indices.step

  override fun iterator(): Iterator<NodeIndex> = indices.asSequence().map(::NodeIndex).iterator()
}
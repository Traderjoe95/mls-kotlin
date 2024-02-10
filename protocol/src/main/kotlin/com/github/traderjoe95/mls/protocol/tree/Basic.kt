package com.github.traderjoe95.mls.protocol.tree

import arrow.core.prependTo
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.util.shl

fun RatchetTree.directPath(node: UInt): List<UInt> =
  if (node >= size || node == root) {
    emptyList()
  } else {
    var current = node
    val path = mutableListOf<UInt>()

    while (current != root) {
      current = current.parent
      path.add(current)
    }

    path.toList()
  }

fun RatchetTree.coPath(node: UInt): List<UInt> =
  node.prependTo(directPath(node))
    .dropLast(1)
    .map { it.sibling }

fun RatchetTree.filteredDirectPath(node: UInt): List<UInt> =
  directPath(node).zip(coPath(node)).filterNot { (_, coPathChild) ->
    resolution(coPathChild).isEmpty()
  }.map { it.first }

fun RatchetTree.resolution(node: UInt): List<UInt> =
  if (node >= size) {
    emptyList()
  } else {
    val toResolve = mutableListOf(node)
    val resolution = mutableListOf<UInt>()

    while (toResolve.isNotEmpty()) {
      val current = toResolve.removeAt(0)

      when {
        current.isBlank && current % 2U == 1U ->
          toResolve.addAll(0, listOf(current.leftChild, current.rightChild))
        !current.isBlank && current % 2U == 0U ->
          resolution.add(current)
        !current.isBlank ->
          resolution.addAll(current.prependTo(this[current]!!.asParent.node.unmergedLeaves.map { it * 2U }))
      }
    }

    resolution.toList()
  }

context(RatchetTree)
fun UInt.isInSubtreeOf(nodeIndex: UInt): Boolean = this in nodeIndex.subtreeRange

context(RatchetTree)
val UInt.subtreeRange: UIntRange
  get() =
    if (this % 2U == 0U) {
      this..this
    } else {
      ((1U shl level) - 1U).let { width -> (this - width)..(this + width) }
    }

fun RatchetTree.lowestCommonAncestor(
  node1: UInt,
  node2: UInt,
): UInt {
  var n1 = node1
  var n2 = node2

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

fun RatchetTree.node(idx: UInt): Node = this[idx]!!.node

fun RatchetTree.parentNode(idx: UInt): ParentNode = this[idx]!!.asParent.node

fun RatchetTree.leafNode(idx: UInt): LeafNode<*> = this[idx]!!.asLeaf.node

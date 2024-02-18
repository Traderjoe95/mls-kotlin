package com.github.traderjoe95.mls.protocol.tree

import arrow.core.prependTo
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.util.shl

fun RatchetTree.directPath(node: TreeIndex): List<NodeIndex> =
  node.nodeIndex.let { nodeIdx ->
    if (nodeIdx >= size || nodeIdx == root) {
      emptyList()
    } else {
      var current = nodeIdx
      val path = mutableListOf<NodeIndex>()

      while (current != root) {
        current = current.parent
        path.add(current)
      }

      path.toList()
    }
  }

fun RatchetTree.coPath(node: TreeIndex): List<NodeIndex> =
  node.nodeIndex.let { nodeIdx ->
    nodeIdx.prependTo(directPath(nodeIdx))
      .dropLast(1)
      .map { it.sibling }
  }

fun RatchetTree.filteredDirectPath(node: TreeIndex): List<NodeIndex> =
  node.nodeIndex.let { nodeIdx ->
    directPath(nodeIdx).zip(coPath(nodeIdx)).filterNot { (_, coPathChild) ->
      resolution(coPathChild).isEmpty()
    }.map { it.first }
  }

fun RatchetTree.resolution(node: TreeIndex): List<NodeIndex> =
  node.nodeIndex.let { nodeIdx ->
    if (nodeIdx >= size) {
      emptyList()
    } else {
      val toResolve = mutableListOf(nodeIdx)
      val result = mutableListOf<NodeIndex>()

      while (toResolve.isNotEmpty()) {
        val current = toResolve.removeAt(0)

        when {
          current.isBlank && current.isParent ->
            toResolve.addAll(0, listOf(current.leftChild, current.rightChild))

          !current.isBlank && current.isLeaf ->
            result.add(current)

          !current.isBlank -> result.addAll(current.prependTo(parentNode(current).unmergedLeaves.map { it.nodeIndex }))
        }
      }

      result.toList()
    }
  }

context(RatchetTree)
fun TreeIndex.isInSubtreeOf(nodeIndex: NodeIndex): Boolean = this.nodeIndex in nodeIndex.subtreeRange

context(RatchetTree)
val TreeIndex.subtreeRange: NodeRange
  get() =
    if (isLeaf) {
      this.nodeIndex..this.nodeIndex
    } else {
      ((1U shl level) - 1U).let { width -> (this.nodeIndex - width)..(this.nodeIndex + width) }
    }

fun RatchetTree.lowestCommonAncestor(
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

fun RatchetTree.node(idx: TreeIndex): Node = this[idx.nodeIndex]!!

fun RatchetTree.parentNode(idx: NodeIndex): ParentNode = this[idx]!!.asParent

fun RatchetTree.leafNode(idx: TreeIndex): LeafNode<*> = this[idx.nodeIndex]!!.asLeaf

fun RatchetTree.leafNodeOrNull(idx: TreeIndex): LeafNode<*>? = this[idx.nodeIndex]?.asLeaf

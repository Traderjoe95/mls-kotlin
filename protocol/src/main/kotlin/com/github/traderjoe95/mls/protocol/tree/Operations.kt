@file:Suppress("kotlin:S1481")

package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import arrow.core.raise.nullable
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.hash.ParentHashInput
import com.github.traderjoe95.mls.protocol.types.tree.hash.ParentHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.tree.hash.TreeHashInput
import com.github.traderjoe95.mls.protocol.types.tree.hash.TreeHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash.Companion.asParentHash

fun RatchetTree.blank(indices: Iterable<TreeIndex>): RatchetTree =
  copy().apply {
    indices.forEach {
      this[it] = null
    }
  }

fun RatchetTree.removeLeaves(leaves: Set<LeafIndex>): RatchetTree =
  if (leaves.isNotEmpty()) {
    blank(leaves.map { it.nodeIndex }).apply {
      if (size > 1U) {
        parentNodeIndices.forEach {
          this[it] = this[it]?.asParent?.run { copy(unmergedLeaves = unmergedLeaves.filterNot(leaves::contains)) }
        }
      }
    }
  } else {
    this
  }

context(ICipherSuite)
val RatchetTree.treeHash: ByteArray
  get() = treeHash(root)

context(ICipherSuite)
fun RatchetTree.treeHash(subtreeRoot: TreeIndex): ByteArray =
  hash(
    if (subtreeRoot.isLeaf) {
      TreeHashInput.forLeaf(subtreeRoot.leafIndex, this@treeHash[subtreeRoot]?.asLeaf).encodeUnsafe()
    } else {
      val subtreeRootIdx = subtreeRoot.nodeIndex
      TreeHashInput.forParent(
        this@treeHash[subtreeRoot]?.asParent,
        treeHash(subtreeRootIdx.leftChild),
        treeHash(subtreeRootIdx.rightChild),
      ).encodeUnsafe()
    },
  )

context(ICipherSuite)
fun RatchetTree.parentHash(
  parentNode: NodeIndex,
  leafNode: TreeIndex,
): ParentHash =
  if (leafNode.nodeIndex == root && parentNode == root) {
    ParentHash.empty
  } else {
    hash(
      (if (parentNode == root) root else parentNode.filteredParent).let { nextNode ->
        ParentHashInput(
          parentNode(parentNode).encryptionKey,
          parentNode(nextNode).parentHash,
          removeLeaves(parentNode(parentNode).unmergedLeaves.toSet()).treeHash(
            if (leafNode.isInSubtreeOf(nextNode.leftChild)) {
              nextNode.rightChild
            } else {
              nextNode.leftChild
            },
          ),
        )
      }.encodeUnsafe(),
    ).asParentHash
  }

context(AuthenticationService<Identity>, Raise<IsSameClientError>)
suspend fun <Identity : Any> RatchetTree.findEquivalentLeaf(keyPackage: KeyPackage): LeafIndex? = findEquivalentLeaf(keyPackage.leafNode)

context(AuthenticationService<Identity>, Raise<IsSameClientError>)
suspend fun <Identity : Any> RatchetTree.findEquivalentLeaf(leafNode: LeafNode<*>): LeafIndex? =
  leaves.zipWithLeafIndex().find { (n, _) ->
    n?.credential?.let { cred ->
      isSameClient(cred, leafNode.credential).bind()
    } ?: false
  }?.second

inline fun RatchetTree.findLeaf(predicate: LeafNode<*>.() -> Boolean): Pair<LeafNode<*>, LeafIndex>? =
  leaves.zipWithLeafIndex()
    .mapNotNull { (maybeNode, idx) ->
      nullable { maybeNode.bind() to idx }
    }
    .find { (n, _) -> n.predicate() }

val RatchetTree.nonBlankParentNodeIndices: List<NodeIndex>
  get() = parentNodeIndices.filterNot { it.isBlank }

val RatchetTree.nonBlankLeafNodeIndices: List<NodeIndex>
  get() = leafNodeIndices.filterNot { it.isBlank }

val RatchetTree.nonBlankLeafIndices: List<LeafIndex>
  get() = leafNodeIndices.filterNot { it.isBlank }.map { it.leafIndex }

val RatchetTree.nonBlankNodeIndices: List<NodeIndex>
  get() = nonBlankParentNodeIndices + nonBlankLeafNodeIndices

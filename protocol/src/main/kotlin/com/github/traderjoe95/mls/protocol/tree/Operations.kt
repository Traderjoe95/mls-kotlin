@file:Suppress("kotlin:S1481")

package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import arrow.core.raise.nullable
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.hash.ParentHashInput
import com.github.traderjoe95.mls.protocol.types.tree.hash.TreeHashInput
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash.Companion.asParentHash
import com.github.traderjoe95.mls.protocol.util.zipWithIndex
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

fun RatchetTree.blank(indices: Iterable<UInt>): RatchetTree =
  copy().apply {
    indices.forEach { this[it] = null }
  }

fun RatchetTree.removeLeaves(leaves: Set<UInt>): RatchetTree =
  if (leaves.isNotEmpty()) {
    blank(leaves.map { it * 2U }).apply {
      if (size > 1U) {
        parentIndices.forEach {
          this[it] =
            this[it]?.asParent?.updateNode {
              copy(unmergedLeaves = unmergedLeaves.filterNot(leaves::contains))
            }
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
fun RatchetTree.treeHash(subtreeRoot: UInt): ByteArray =
  throwAnyError {
    hash(
      TreeHashInput.T.encode(
        if (subtreeRoot % 2U == 0U) {
          TreeHashInput.forLeaf(subtreeRoot, this@treeHash[subtreeRoot]?.asLeaf)
        } else {
          TreeHashInput.forParent(
            this@treeHash[subtreeRoot]?.asParent,
            treeHash(subtreeRoot.leftChild),
            treeHash(subtreeRoot.rightChild),
          )
        },
      ),
    )
  }

context(ICipherSuite, Raise<BaseEncoderError>)
fun RatchetTree.parentHash(
  parentNode: UInt,
  leafNode: UInt,
): ParentHash =
  hash(
    ParentHashInput.T.encode(
      (if (parentNode == root) root else parentNode.filteredParent).let { nextNode ->
        ParentHashInput(
          this[parentNode]!!.node.encryptionKey,
          this[nextNode]!!.asParent.node.parentHash,
          removeLeaves(this[parentNode]!!.asParent.node.unmergedLeaves.toSet()).treeHash(
            if (leafNode.isInSubtreeOf(nextNode.leftChild)) {
              nextNode.rightChild
            } else {
              nextNode.leftChild
            },
          ),
        )
      },
    ),
  ).asParentHash

context(AuthenticationService<Identity>, Raise<IsSameClientError>)
suspend fun <Identity : Any> RatchetTree.findEquivalentLeaf(keyPackage: KeyPackage): UInt? = findEquivalentLeaf(keyPackage.leafNode)

context(AuthenticationService<Identity>, Raise<IsSameClientError>)
suspend fun <Identity : Any> RatchetTree.findEquivalentLeaf(leafNode: LeafNode<*>): UInt? =
  leaves.zipWithIndex().find { (n, _) ->
    n?.node?.credential?.let { cred ->
      isSameClient(cred, leafNode.credential).bind()
    } ?: false
  }?.let { it.second.toUInt() * 2U }

inline fun RatchetTree.findLeaf(predicate: LeafNode<*>.() -> Boolean): Pair<LeafNode<*>, UInt>? =
  leaves.zipWithIndex()
    .mapNotNull { (maybeNode, idx) ->
      nullable { maybeNode?.node.bind() to idx.toUInt() }
    }
    .find { (n, _) -> n.predicate() }

val RatchetTree.nonBlankParentNodes: List<UInt>
  get() = parentIndices.filterNot { it.isBlank }

val RatchetTree.nonBlankLeafNodes: List<UInt>
  get() = leafIndices.filterNot { it.isBlank }

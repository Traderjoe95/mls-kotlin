package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.DuplicateEncryptionKey
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.TreeCheckError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.util.zipWithIndex

context(ApplicationCtx<Identity>, ICipherSuite, Raise<TreeCheckError>)
suspend fun <Identity : Any> RatchetTree.check(groupContext: GroupContext) =
  EncoderError.wrap {
    treeHash.let { th ->
      if (th.contentEquals(groupContext.treeHash).not()) {
        raise(TreeCheckError.BadTreeHash(groupContext.treeHash, th))
      }
    }

    checkParentHashCoverage()

    nonBlankParentNodes.forEach { parentIdx ->
      val parentNode = parentNode(parentIdx)

      parentNode.checkUnmergedLeaves(parentIdx)

      (nonBlankLeafNodes + nonBlankParentNodes).filter {
        it != parentIdx && node(it).encryptionKey.eq(parentNode.encryptionKey)
      }.sorted().let {
        if (it.isNotEmpty()) raise(DuplicateEncryptionKey(it))
      }
    }

    nonBlankLeafNodes.forEach {
      this@RatchetTree[it]!!.asLeaf.node.validate(groupContext, it / 2U)
    }
  }

context(ICipherSuite, Raise<TreeCheckError>)
private fun RatchetTree.checkParentHashCoverage() =
  EncoderError.wrap {
    val phCoverage = mutableMapOf<UInt, UInt>()

    leaves.zipWithIndex().mapNotNull { (l, leafIdx) ->
      l?.let { it.node to leafIdx.toUInt() * 2U }
    }.forEach { (leaf, leafNodeIdx) ->
      var currentRefNode: Node = leaf
      var currentNode = leafNodeIdx

      while (currentNode != root) {
        currentNode = currentNode.parent

        if (currentNode.isBlank && currentNode != root) {
          continue
        } else if (currentNode.isBlank) {
          break
        }

        val ph = parentHash(currentNode, leafNodeIdx)

        if (ph.value.contentEquals(currentRefNode.parentHash?.value)) {
          phCoverage.compute(currentNode) { _, value ->
            (value ?: 0U) + 1U
          }

          currentRefNode = parentNode(currentNode)
        } else {
          break
        }
      }
    }

    nonBlankParentNodes.forEach { parentIdx ->
      if (phCoverage.getOrDefault(parentIdx, 0U) != 1U) raise(TreeCheckError.NotParentHashValid(parentIdx))
    }
  }

context(ICipherSuite, RatchetTree, Raise<TreeCheckError>)
private fun ParentNode.checkUnmergedLeaves(parentIdx: UInt) {
  unmergedLeaves.forEach { leafIdx ->
    val leafNodeIdx = leafIdx * 2U
    if (leafNodeIdx.isBlank) raise(TreeCheckError.BadUnmergedLeaf(parentIdx, leafIdx, "Leaf node is blank"))
    if (leafNodeIdx.isInSubtreeOf(parentIdx).not()) {
      raise(
        TreeCheckError.BadUnmergedLeaf(
          parentIdx,
          leafIdx,
          "Not a descendant",
        ),
      )
    }

    var currentNode = leafNodeIdx.parent
    while (currentNode != parentIdx) {
      if (currentNode.isBlank.not() && leafIdx !in parentNode(currentNode).unmergedLeaves) {
        raise(
          TreeCheckError.BadUnmergedLeaf(
            parentIdx,
            leafIdx,
            "Not in unmerged leaf of intermediate node $currentNode",
          ),
        )
      }
      currentNode = currentNode.parent
    }
  }
}

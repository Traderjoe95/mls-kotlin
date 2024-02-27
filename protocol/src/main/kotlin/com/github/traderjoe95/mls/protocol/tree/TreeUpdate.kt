package com.github.traderjoe95.mls.protocol.tree

import arrow.core.prependTo
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.error.RecipientTreeUpdateError
import com.github.traderjoe95.mls.protocol.error.SenderTreeUpdateError
import com.github.traderjoe95.mls.protocol.error.WrongParentHash
import com.github.traderjoe95.mls.protocol.error.WrongUpdatePathLength
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.types.RefinedBytes.Companion.neqNullable
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePathNode
import com.github.traderjoe95.mls.protocol.util.foldWith

context(Raise<SenderTreeUpdateError>)
internal fun createUpdatePath(
  originalTree: RatchetTree,
  excludeNewLeaves: Set<LeafIndex>,
  groupContext: GroupContext,
  signaturePrivateKey: SignaturePrivateKey,
): Triple<RatchetTree, UpdatePath, List<Secret>> =
  createUpdatePath(originalTree, originalTree.leafIndex, excludeNewLeaves, groupContext, signaturePrivateKey)

context(Raise<SenderTreeUpdateError>)
internal fun createUpdatePath(
  originalTree: RatchetTree,
  from: LeafIndex,
  excludeNewLeaves: Set<LeafIndex>,
  groupContext: GroupContext,
  signaturePrivateKey: SignaturePrivateKey,
): Triple<RatchetTree, UpdatePath, List<Secret>> =
  with(originalTree.cipherSuite) {
    val oldLeafNode = originalTree.leafNode(from)

    val leafPathSecret = generateSecret(hashLen)
    val leafNodeSecret = deriveSecret(leafPathSecret, "node")
    val leafKp = deriveKeyPair(leafNodeSecret)

    val directPath = originalTree.directPath(from)
    val directPathToCoPath = directPath.zip(originalTree.coPath(from)).toMap()
    val filteredDirectPath = originalTree.filteredDirectPath(from)

    val pathSecrets = mutableListOf(leafPathSecret)

    val updatedTreeWithoutLeaf =
      originalTree
        .blank(directPath)
        .foldWith(filteredDirectPath) { nodeIdx ->
          val newPathSecret = deriveSecret(pathSecrets.last(), "path").also(pathSecrets::add)
          val nodeSecret = deriveSecret(newPathSecret, "node")
          val nodeKp = deriveKeyPair(nodeSecret)
          nodeSecret.wipe()

          set(nodeIdx, ParentNode.new(nodeKp.public), newPathSecret)
        }
        .foldWith(
          from.nodeIndex.prependTo(filteredDirectPath).zipWithNext().reversed(),
        ) { (nodeIdx, parent) ->
          updateOrNull(nodeIdx) { withParentHash(parentHash = parentHash(cipherSuite, parent, from)) }
        }

    val newLeafNode =
      LeafNode.commit(
        originalTree.cipherSuite,
        leafKp.public,
        oldLeafNode,
        updatedTreeWithoutLeaf.parentHash(
          originalTree.cipherSuite,
          filteredDirectPath.firstOrNull() ?: originalTree.root,
          from,
        ),
        from,
        groupContext.groupId,
        signaturePrivateKey,
      )
    val updatedTree =
      updatedTreeWithoutLeaf.set(
        from,
        newLeafNode,
        leafKp.private,
      )

    val provisionalGroupCtx = groupContext.provisional(updatedTree)
    val excludedNodeIndices = excludeNewLeaves.map { it.nodeIndex }.toSet()

    val updatePathNodes =
      filteredDirectPath.zip(pathSecrets.drop(1)).map { (nodeIdx, pathSecret) ->
        val encryptFor = updatedTree.resolution(directPathToCoPath[nodeIdx]!!) - excludedNodeIndices

        UpdatePathNode(
          updatedTree.parentNode(nodeIdx).encryptionKey,
          encryptFor.map { idx ->
            encryptWithLabel(
              originalTree.node(idx).encryptionKey,
              "UpdatePathNode",
              provisionalGroupCtx.encoded,
              pathSecret.bytes,
            )
          },
        )
      }

    return Triple(
      updatedTree,
      UpdatePath(newLeafNode, updatePathNodes),
      pathSecrets.drop(1),
    )
  }

context(Raise<RecipientTreeUpdateError>)
internal fun applyUpdatePath(
  originalTree: RatchetTree,
  groupContext: GroupContext,
  fromLeafIndex: LeafIndex,
  updatePath: UpdatePath,
  excludeNewLeaves: Set<LeafIndex>,
): Pair<RatchetTree, Secret> {
  var updatedTree = originalTree.mergeUpdatePath(fromLeafIndex, updatePath)

  val provisionalGroupCtx = groupContext.provisional(updatedTree)

  val excludedNodeIndices = excludeNewLeaves.map { it.nodeIndex }.toSet()
  val (commonAncestor, pathSecret) =
    updatedTree.findPathSecret(
      fromLeafIndex,
      updatePath,
      provisionalGroupCtx,
      excludedNodeIndices,
    )

  updatedTree = updatedTree.insertPathSecrets(commonAncestor, pathSecret)

  return updatedTree to updatedTree.private.commitSecret
}

context(ICipherSuite, Raise<RecipientTreeUpdateError>)
internal fun RatchetTree.applyUpdatePathExternalJoin(
  groupContext: GroupContext,
  updatePath: UpdatePath,
  excludeNewLeaves: Set<LeafIndex>,
): Pair<RatchetTree, Secret> =
  insert(updatePath.leafNode).let { (tree, newLeaf) ->
    applyUpdatePath(tree, groupContext, newLeaf, updatePath, excludeNewLeaves)
  }

context(Raise<RecipientTreeUpdateError>)
internal fun RatchetTree.mergeUpdatePath(
  fromLeafIdx: LeafIndex,
  updatePath: UpdatePath,
): RatchetTree {
  val directPath = directPath(fromLeafIdx)
  val filteredDirectPath = filteredDirectPath(fromLeafIdx)

  if (filteredDirectPath.uSize != updatePath.size) {
    raise(WrongUpdatePathLength(filteredDirectPath.uSize, updatePath.size))
  }

  return blank(directPath)
    .foldWith(filteredDirectPath.zip(updatePath.nodes)) { (nodeIdx, updateNode) ->
      set(nodeIdx, ParentNode.new(updateNode.encryptionKey))
    }
    .foldWith(filteredDirectPath.zipWithNext().reversed()) { (nodeIdx, parent) ->
      updateOrNull(nodeIdx) { withParentHash(parentHash = parentHash(cipherSuite, parent, fromLeafIdx)) }
    }
    .let { updatedWithoutLeaf ->
      val computedParentHash = updatedWithoutLeaf.parentHash(cipherSuite, filteredDirectPath.first(), fromLeafIdx)

      if (updatePath.leafNode.parentHash neqNullable computedParentHash) {
        raise(WrongParentHash(computedParentHash.bytes, updatePath.leafNode.parentHash!!.bytes))
      }

      updatedWithoutLeaf.set(fromLeafIdx, updatePath.leafNode)
    }
}

internal fun RatchetTree.findPathSecret(
  fromLeafIdx: LeafIndex,
  updatePath: UpdatePath,
  groupContext: GroupContext,
  excludeNewLeaves: Set<NodeIndex>,
): Pair<NodeIndex, Secret> {
  val filteredDirectPath = filteredDirectPath(fromLeafIdx)
  val directPathToCoPath = directPath(fromLeafIdx).zip(coPath(fromLeafIdx)).toMap()

  for ((nodeIdx, updateNode) in filteredDirectPath.zip(updatePath.nodes)) {
    if (!leafIndex.isInSubtreeOf(nodeIdx)) continue

    val nonUpdatedChild = directPathToCoPath[nodeIdx]!!

    val pathSecret =
      (resolution(nonUpdatedChild) - excludeNewLeaves)
        .zip(updateNode.encryptedPathSecret)
        .firstNotNullOf { (node, ciphertext) -> getKeyPair(node)?.let(ciphertext::to) }
        .let { (ciphertext, keyPair) ->
          cipherSuite.decryptWithLabel(
            keyPair,
            "UpdatePathNode",
            groupContext.encoded,
            ciphertext,
          ).asSecret
        }

    return nodeIdx to pathSecret
  }

  error("Own node not found in update path")
}

context(ICipherSuite, Raise<JoinError>)
internal fun RatchetTree.insertPathSecrets(
  ownLeafIdx: LeafIndex,
  senderLeafIdx: LeafIndex,
  pathSecret: Secret,
): RatchetTree {
  return insertPathSecrets(
    filteredDirectPath(senderLeafIdx).find { ownLeafIdx.isInSubtreeOf(it) && senderLeafIdx.isInSubtreeOf(it) }!!,
    pathSecret,
  )
}

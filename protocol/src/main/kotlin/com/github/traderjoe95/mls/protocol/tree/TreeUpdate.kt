package com.github.traderjoe95.mls.protocol.tree

import arrow.core.prependTo
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.error.PublicKeyMismatch
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
import com.github.traderjoe95.mls.protocol.util.zipWithIndex

context(Raise<SenderTreeUpdateError>)
internal fun createUpdatePath(
  originalTree: RatchetTree,
  excludeNewLeaves: Set<LeafIndex>,
  groupContext: GroupContext,
  signaturePrivateKey: SignaturePrivateKey,
): Triple<RatchetTree, UpdatePath, List<Secret>> =
  with(originalTree.cipherSuite) {
    val oldLeafNode = originalTree.leafNode(originalTree.leafIndex)

    val leafPathSecret = generateSecret(hashLen)
    val leafNodeSecret = deriveSecret(leafPathSecret, "node")
    val leafKp = deriveKeyPair(leafNodeSecret)

    val directPath = originalTree.directPath(originalTree.leafIndex)
    val directPathToCoPath = directPath.zip(originalTree.coPath(originalTree.leafIndex)).toMap()
    val filteredDirectPath = originalTree.filteredDirectPath(originalTree.leafIndex)

    val pathSecrets = mutableListOf(leafPathSecret)

    val updatedTreeWithoutLeaf =
      originalTree
        .blank(directPath)
        .foldWith(filteredDirectPath) { nodeIdx ->
          val newPathSecret = deriveSecret(pathSecrets.last(), "path").also(pathSecrets::add)
          val nodeSecret = deriveSecret(newPathSecret, "node")
          val nodeKp = deriveKeyPair(nodeSecret)
          nodeSecret.wipe()

          set(nodeIdx, ParentNode.new(nodeKp.public), nodeKp.private)
        }
        .foldWith(
          originalTree.leafIndex.nodeIndex.prependTo(filteredDirectPath).zipWithNext().reversed(),
        ) { (nodeIdx, parent) ->
          updateOrNull(nodeIdx) { withParentHash(parentHash = parentHash(parent, leafIndex)) }
        }

    val newLeafNode =
      LeafNode.commit(
        groupContext.cipherSuite,
        leafKp.public,
        oldLeafNode,
        updatedTreeWithoutLeaf.parentHash(
          filteredDirectPath.firstOrNull() ?: originalTree.root,
          originalTree.leafIndex,
        ),
        originalTree.leafIndex,
        groupContext,
        signaturePrivateKey,
      )
    val updatedTree =
      updatedTreeWithoutLeaf.set(
        originalTree.leafIndex,
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
): Pair<RatchetTree, Secret> =
  with(originalTree.cipherSuite) {
    val directPath = originalTree.directPath(fromLeafIndex)
    val directPathToCoPath = directPath.zip(originalTree.coPath(fromLeafIndex)).toMap()
    val filteredDirectPath = originalTree.filteredDirectPath(fromLeafIndex)

    if (filteredDirectPath.uSize != updatePath.size) {
      raise(WrongUpdatePathLength(filteredDirectPath.uSize, updatePath.size))
    }

    val updatedTreeWithoutLeaf =
      originalTree
        .blank(directPath)
        .foldWith(filteredDirectPath.zip(updatePath.nodes)) { (nodeIdx, updateNode) ->
          set(nodeIdx, ParentNode.new(updateNode.encryptionKey))
        }
        .foldWith(filteredDirectPath.zipWithNext().reversed()) { (nodeIdx, parent) ->
          updateOrNull(nodeIdx) { withParentHash(parentHash = parentHash(parent, fromLeafIndex)) }
        }

    val computedParentHash = updatedTreeWithoutLeaf.parentHash(filteredDirectPath.first(), fromLeafIndex)
    if (updatePath.leafNode.parentHash neqNullable computedParentHash) {
      raise(WrongParentHash(computedParentHash.bytes, updatePath.leafNode.parentHash!!.bytes))
    }

    var updatedTree = updatedTreeWithoutLeaf.set(fromLeafIndex, updatePath.leafNode)

    val provisionalGroupCtx = groupContext.provisional(updatedTree)
    var pathSecret: Secret? = null

    val excludedNodeIndices = excludeNewLeaves.map { it.nodeIndex }.toSet()

    for ((nodeIdx, updateNode) in filteredDirectPath.zip(updatePath.nodes)) {
      val nonUpdatedChild = directPathToCoPath[nodeIdx]!!

      pathSecret =
        if (pathSecret == null && updatedTree.leafIndex.isInSubtreeOf(nonUpdatedChild)) {
          (updatedTree.resolution(nonUpdatedChild) - excludedNodeIndices)
            .zipWithIndex()
            .firstNotNullOfOrNull { (nodeIdx, idx) ->
              updatedTree.getKeyPair(nodeIdx)?.let { idx to it }
            }
            ?.let { (resolutionIdx, keyPair) ->
              decryptWithLabel(
                keyPair,
                "UpdatePathNode",
                provisionalGroupCtx.encoded,
                updateNode.encryptedPathSecret[resolutionIdx],
              ).asSecret
            }
        } else if (pathSecret != null) {
          val newPathSecret = deriveSecret(pathSecret, "path")
          pathSecret.wipe()
          newPathSecret
        } else {
          null
        }

      val nodePrivate =
        pathSecret?.let {
          val nodeSecret = deriveSecret(it, "node")

          deriveKeyPair(nodeSecret).apply {
            if (public.eq(updateNode.encryptionKey).not()) {
              raise(PublicKeyMismatch(public, updateNode.encryptionKey))
            }
          }.private.also { nodeSecret.wipe() }
        }

      if (nodePrivate != null) {
        updatedTree = updatedTree.set(nodeIdx, nodePrivate)
      }
    }

    return updatedTree to deriveSecret(pathSecret!!, "path").also { pathSecret.wipe() }
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

context(ICipherSuite, Raise<JoinError>)
internal fun RatchetTree.updateOnJoin(
  ownLeafIdx: LeafIndex,
  senderLeafIdx: LeafIndex,
  pathSecret: Secret,
): RatchetTree {
  var currentIdx = lowestCommonAncestor(ownLeafIdx, senderLeafIdx)
  var currentPathSecret = pathSecret
  var currentTree = nodeKeyUpdate(currentIdx, currentPathSecret)

  while (currentIdx != root) {
    currentIdx = currentIdx.parent

    if (!currentIdx.isBlank) {
      currentPathSecret = deriveSecret(currentPathSecret, "path")

      currentTree = currentTree.nodeKeyUpdate(currentIdx, currentPathSecret)
    }
  }

  return currentTree
}

context(ICipherSuite, Raise<PublicKeyMismatch>)
private fun RatchetTree.nodeKeyUpdate(
  nodeIdx: NodeIndex,
  pathSecret: Secret,
): RatchetTree {
  val nodeSecret = deriveSecret(pathSecret, "node")
  val (nodePrivate, nodePublic) = deriveKeyPair(nodeSecret)
  nodeSecret.wipe()

  val node = parentNode(nodeIdx)

  if (node.encryptionKey.eq(nodePublic).not()) {
    raise(PublicKeyMismatch(nodePublic, node.encryptionKey))
  }

  return set(nodeIdx, nodePrivate)
}

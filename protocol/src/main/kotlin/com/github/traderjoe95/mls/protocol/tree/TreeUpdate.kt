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
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.framing.message.PathSecret
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePathNode
import com.github.traderjoe95.mls.protocol.util.zipWithIndex

context(ICipherSuite, Raise<SenderTreeUpdateError>)
internal fun RatchetTree.updatePath(
  excludeNewLeaves: Set<LeafIndex>,
  ownLeafIndex: LeafIndex,
  groupContext: GroupContext,
  signingKey: SigningKey,
  privateKeyStore: TreePrivateKeyStore,
): Triple<RatchetTree, UpdatePath, List<Secret>> {
  val oldLeafNode = leafNode(ownLeafIndex)

  val leafPathSecret = generateSecret(hashLen)
  val leafNodeSecret = deriveSecret(leafPathSecret, "node")
  val leafKp = deriveKeyPair(leafNodeSecret)

  val updatePathNodes = mutableListOf<UpdatePathNode>()

  val directPath = directPath(ownLeafIndex)
  val directPathToCoPath = directPath.zip(coPath(ownLeafIndex)).toMap()

  return blank(directPath).run {
    val filteredPath = filteredDirectPath(ownLeafIndex)

    val pathSecrets = mutableListOf(leafPathSecret)

    for (nodeIdx in filteredPath) {
      val newPathSecret = deriveSecret(pathSecrets.last(), "path").also(pathSecrets::add)

      val nodeSecret = deriveSecret(newPathSecret, "node")
      val nodeKp = deriveKeyPair(nodeSecret)
      nodeSecret.wipe()

      this[nodeIdx] = ParentNode.new(nodeKp.public)
      privateKeyStore.storePrivateKey(nodeKp)
    }

    for ((nodeIdx, parent) in ownLeafIndex.nodeIndex.prependTo(filteredPath).zipWithNext().reversed()) {
      this[nodeIdx] = this[nodeIdx]?.withParentHash(parentHash = parentHash(parent, ownLeafIndex))
    }
    leafNodeSecret.wipe()

    val newLeafNode =
      LeafNode.commit(
        leafKp.public,
        oldLeafNode,
        parentHash(filteredPath.firstOrNull() ?: root, ownLeafIndex),
        ownLeafIndex,
        groupContext,
        signingKey,
      )

    this[ownLeafIndex] = newLeafNode
    privateKeyStore.storePrivateKey(leafKp)

    val provisionalGroupCtx = groupContext.provisional(this)

    val excludedNodeIndices = excludeNewLeaves.map { it.nodeIndex }.toSet()

    for ((nodeIdx, pathSecret) in filteredPath.zip(pathSecrets.drop(1))) {
      val encryptFor = resolution(directPathToCoPath[nodeIdx]!!) - excludedNodeIndices

      updatePathNodes.add(
        UpdatePathNode(
          parentNode(nodeIdx).encryptionKey,
          encryptFor.map { idx ->
            encryptWithLabel(
              node(idx).encryptionKey,
              "UpdatePathNode",
              provisionalGroupCtx.encoded,
              pathSecret.key,
            )
          },
        ),
      )
    }

    Triple(
      this,
      UpdatePath(newLeafNode, updatePathNodes),
      pathSecrets.drop(1),
    )
  }
}

context(ICipherSuite, Raise<RecipientTreeUpdateError>)
internal fun RatchetTree.applyUpdatePath(
  ownLeafIndex: LeafIndex,
  groupContext: GroupContext,
  fromLeafIndex: LeafIndex,
  updatePath: UpdatePath,
  excludeNewLeaves: Set<LeafIndex>,
  privateKeyStore: TreePrivateKeyStore,
): Pair<RatchetTree, Secret> {
  val directPath = directPath(fromLeafIndex)
  val directPathToCoPath = directPath.zip(coPath(fromLeafIndex)).toMap()

  return blank(directPath).run {
    val filteredPath = filteredDirectPath(fromLeafIndex)

    if (filteredPath.uSize != updatePath.size) {
      raise(WrongUpdatePathLength(filteredPath.uSize, updatePath.size))
    }

    for ((nodeIdx, updateNode) in filteredPath.zip(updatePath.nodes)) {
      this[nodeIdx] = ParentNode.new(updateNode.encryptionKey)
    }

    for ((nodeIdx, parent) in filteredPath.zipWithNext().reversed()) {
      this[nodeIdx] = this[nodeIdx]?.withParentHash(parentHash = parentHash(parent, fromLeafIndex))
    }

    val computedParentHash = parentHash(filteredPath.first(), fromLeafIndex)
    if (updatePath.leafNode.parentHash != computedParentHash) {
      raise(WrongParentHash(computedParentHash.value, updatePath.leafNode.parentHash!!.value))
    }

    this[fromLeafIndex] = updatePath.leafNode

    val provisionalGroupCtx = groupContext.provisional(this)
    var pathSecret: Secret? = null

    val excludedNodeIndices = excludeNewLeaves.map { it.nodeIndex }.toSet()

    for ((nodeIdx, updateNode) in filteredPath.zip(updatePath.nodes)) {
      val nonUpdatedChild = directPathToCoPath[nodeIdx]!!

      pathSecret =
        if (pathSecret == null && ownLeafIndex.isInSubtreeOf(nonUpdatedChild)) {
          (resolution(nonUpdatedChild) - excludedNodeIndices).zipWithIndex().firstNotNullOfOrNull { (nodeIdx, idx) ->
            this[nodeIdx]?.encryptionKey?.let(privateKeyStore::getKeyPairFor)?.let { idx to it }
          }?.let { (resolutionIdx, keyPair) ->
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
        privateKeyStore.storePrivateKey(updateNode.encryptionKey, nodePrivate)
      }
    }

    this to deriveSecret(pathSecret!!, "path").also { pathSecret.wipe() }
  }
}

context(ICipherSuite, Raise<RecipientTreeUpdateError>)
internal fun RatchetTree.applyUpdatePathExternalJoin(
  ownLeafIndex: LeafIndex,
  groupContext: GroupContext,
  updatePath: UpdatePath,
  excludeNewLeaves: Set<LeafIndex>,
  privateKeyStore: TreePrivateKeyStore,
): Pair<RatchetTree, Secret> =
  insert(updatePath.leafNode).let { (tree, newLeaf) ->
    tree.applyUpdatePath(ownLeafIndex, groupContext, newLeaf, updatePath, excludeNewLeaves, privateKeyStore)
  }

context(ICipherSuite, Raise<JoinError>)
internal fun RatchetTree.updateOnJoin(
  ownLeafIdx: LeafIndex,
  senderLeafIdx: LeafIndex,
  pathSecret: PathSecret,
  privateKeyStore: TreePrivateKeyStore,
): RatchetTree =
  copy().apply {
    var currentIdx = lowestCommonAncestor(ownLeafIdx, senderLeafIdx)
    var currentPathSecret = pathSecret.pathSecret

    nodeKeyUpdate(currentIdx, currentPathSecret, privateKeyStore)

    while (currentIdx != root) {
      currentIdx = currentIdx.parent

      if (!currentIdx.isBlank) {
        currentPathSecret = deriveSecret(currentPathSecret, "path")

        nodeKeyUpdate(currentIdx, currentPathSecret, privateKeyStore)
      }
    }
  }

context(ICipherSuite, Raise<PublicKeyMismatch>)
private fun RatchetTree.nodeKeyUpdate(
  nodeIdx: NodeIndex,
  pathSecret: Secret,
  privateKeyStore: TreePrivateKeyStore,
) {
  val nodeSecret = deriveSecret(pathSecret, "node")
  val (nodePrivate, nodePublic) = deriveKeyPair(nodeSecret)
  nodeSecret.wipe()

  val node = parentNode(nodeIdx)

  if (node.encryptionKey.eq(nodePublic).not()) {
    raise(PublicKeyMismatch(nodePublic, node.encryptionKey))
  }

  privateKeyStore.storePrivateKey(nodePublic, nodePrivate)
}

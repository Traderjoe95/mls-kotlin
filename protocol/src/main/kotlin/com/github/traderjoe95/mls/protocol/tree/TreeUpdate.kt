package com.github.traderjoe95.mls.protocol.tree

import arrow.core.prependTo
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.JoinError
import com.github.traderjoe95.mls.protocol.error.PublicKeyMismatch
import com.github.traderjoe95.mls.protocol.error.RecipientTreeUpdateError
import com.github.traderjoe95.mls.protocol.error.SenderTreeUpdateError
import com.github.traderjoe95.mls.protocol.error.WrongParentHash
import com.github.traderjoe95.mls.protocol.error.WrongUpdatePathLength
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.framing.message.PathSecret
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePathNode
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.protocol.util.zipWithIndex
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

context(ICipherSuite, Raise<SenderTreeUpdateError>)
fun RatchetTree.updatePath(
  excludeNewLeaves: Set<UInt>,
  ownLeafIndex: UInt,
  groupContext: GroupContext,
  signingKey: SigningKey,
): Triple<RatchetTree, UpdatePath, List<Secret>> =
  EncoderError.wrap {
    val oldLeafNode = leaves[ownLeafIndex]!!.asLeaf.node

    val leafPathSecret = generateSecret(hashLen)
    val leafNodeSecret = deriveSecret(leafPathSecret, "node")
    val leafKp = deriveKeyPair(leafNodeSecret)

    val updatePathNodes = mutableListOf<UpdatePathNode>()

    val directPath = directPath(ownLeafIndex.leafNodeIndex)
    val directPathToCoPath = directPath.zip(coPath(ownLeafIndex.leafNodeIndex)).toMap()

    blank(directPath).run {
      val filteredPath = filteredDirectPath(ownLeafIndex.leafNodeIndex)

      val pathSecrets = mutableListOf(leafPathSecret)

      for (nodeIdx in filteredPath) {
        val newPathSecret = deriveSecret(pathSecrets.last(), "path").also(pathSecrets::add)

        val nodeSecret = deriveSecret(newPathSecret, "node")
        val nodeKp = deriveKeyPair(nodeSecret)
        nodeSecret.wipe()

        this[nodeIdx] = ParentNodeRecord.new(nodeKp)
      }

      for ((nodeIdx, parent) in ownLeafIndex.leafNodeIndex.prependTo(filteredPath).zipWithNext().reversed()) {
        @Suppress("UNCHECKED_CAST")
        this[nodeIdx] =
          (this[nodeIdx] as NodeRecord<Node>?)?.updateNode {
            withParentHash(parentHash = parentHash(parent, ownLeafIndex.leafNodeIndex))
          }
      }
      leafNodeSecret.wipe()

      val newLeafNode =
        LeafNode.commit(
          leafKp.public,
          oldLeafNode,
          parentHash(filteredPath.first(), ownLeafIndex.leafNodeIndex),
          ownLeafIndex,
          groupContext,
          signingKey,
        )

      this[ownLeafIndex.leafNodeIndex] = LeafNodeRecord(newLeafNode to leafKp.private)

      val provisionalGroupCtx = groupContext.provisional(this)
      for ((nodeIdx, pathSecret) in filteredPath.zip(pathSecrets.drop(1))) {
        val encryptFor = resolution(directPathToCoPath[nodeIdx]!!) - excludeNewLeaves
        updatePathNodes.add(
          UpdatePathNode(
            this[nodeIdx]!!.publicKey,
            encryptFor.map { idx ->
              encryptWithLabel(
                this[idx]!!.node.encryptionKey,
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
fun RatchetTree.applyUpdatePath(
  ownLeafIndex: UInt,
  groupContext: GroupContext,
  fromLeafIndex: UInt,
  updatePath: UpdatePath,
  excludeNewLeaves: Set<UInt>,
): Pair<RatchetTree, Secret> =
  EncoderError.wrap {
    val directPath = directPath(fromLeafIndex.leafNodeIndex)
    val directPathToCoPath = directPath.zip(coPath(fromLeafIndex.leafNodeIndex)).toMap()

    blank(directPath).run {
      val filteredPath = filteredDirectPath(fromLeafIndex.leafNodeIndex)

      if (filteredPath.uSize != updatePath.size) {
        raise(WrongUpdatePathLength(filteredPath.uSize, updatePath.size))
      }

      for ((nodeIdx, updateNode) in filteredPath.zip(updatePath.nodes)) {
        this[nodeIdx] = ParentNodeRecord.new(updateNode.encryptionKey, null)
      }

      for ((nodeIdx, parent) in filteredPath.zipWithNext().reversed()) {
        this[nodeIdx] =
          this[nodeIdx]?.asParent?.updateNode {
            copy(parentHash = parentHash(parent, fromLeafIndex))
          }
      }

      val computedParentHash = parentHash(filteredPath.first(), fromLeafIndex.leafNodeIndex)
      if (updatePath.leafNode.parentHash != computedParentHash) {
        raise(WrongParentHash(computedParentHash.value, updatePath.leafNode.parentHash!!.value))
      }

      this[fromLeafIndex.leafNodeIndex] = updatePath.leafNode

      val provisionalGroupCtx = groupContext.provisional(this)
      var pathSecret: Secret? = null

      for ((nodeIdx, updateNode) in filteredPath.zip(updatePath.nodes)) {
        val nonUpdatedChild = directPathToCoPath[nodeIdx]!!

        pathSecret =
          if (pathSecret == null && ownLeafIndex.leafNodeIndex.isInSubtreeOf(nonUpdatedChild)) {
            (resolution(nonUpdatedChild) - excludeNewLeaves).zipWithIndex().firstNotNullOfOrNull { (nodeIdx, idx) ->
              this[nodeIdx]?.keyPair?.let { idx to it }
            }?.let { (resolutionIdx, privateKey) ->
              decryptWithLabel(
                privateKey,
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

        this[nodeIdx] = this[nodeIdx]!!.asParent.withPrivateKey(nodePrivate)
      }

      this to deriveSecret(pathSecret!!, "path").also { pathSecret.wipe() }
    }
  }

context(GroupState, Raise<RecipientTreeUpdateError>)
fun RatchetTree.applyUpdatePathExternalJoin(
  ownLeafIndex: UInt,
  groupContext: GroupContext,
  updatePath: UpdatePath,
  excludeNewLeaves: Set<UInt>,
): Pair<RatchetTree, Secret> =
  insert(updatePath.leafNode).let { (tree, newLeaf) ->
    tree.applyUpdatePath(ownLeafIndex, groupContext, newLeaf, updatePath, excludeNewLeaves)
  }

context(ICipherSuite, Raise<JoinError>)
fun RatchetTree.updateOnJoin(
  ownLeafNodeIdx: UInt,
  senderLeafNodeIdx: UInt,
  pathSecret: PathSecret,
): RatchetTree =
  EncoderError.wrap {
    copy().apply {
      var currentIdx = lowestCommonAncestor(ownLeafNodeIdx, senderLeafNodeIdx)
      var currentPathSecret = pathSecret.pathSecret

      nodeKeyUpdate(currentIdx, currentPathSecret)

      while (currentIdx != root) {
        currentIdx = currentIdx.parent

        if (!currentIdx.isBlank) {
          currentPathSecret = deriveSecret(currentPathSecret, "path")

          nodeKeyUpdate(currentIdx, currentPathSecret)
        }
      }
    }
  }

context(ICipherSuite, Raise<BaseEncoderError>, Raise<PublicKeyMismatch>)
private fun RatchetTree.nodeKeyUpdate(
  nodeIdx: UInt,
  pathSecret: Secret,
) {
  val nodeSecret = deriveSecret(pathSecret, "node")
  val (nodePrivate, nodePublic) = deriveKeyPair(nodeSecret)
  nodeSecret.wipe()

  val node = parentNode(nodeIdx)

  if (node.encryptionKey.eq(nodePublic).not()) {
    raise(PublicKeyMismatch(nodePublic, node.encryptionKey))
  }

  this[nodeIdx] = ParentNodeRecord(node to nodePrivate)
}

fun RatchetTree.applyUpdate(
  update: Update,
  leafIndex: UInt,
  privateKey: HpkePrivateKey? = null,
): RatchetTree =
  blank(directPath(leafIndex).dropLast(1)).apply {
    this[leafIndex] = LeafNodeRecord(update.leafNode to privateKey)
  }

package com.github.traderjoe95.mls.protocol.interop.tree

import arrow.core.raise.nullable
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.FullTree
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.InternalBlanksNoSkipping
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.InternalBlanksWithSkipping
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.UnmergedLeavesNoSkipping
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.UnmergedLeavesWithSkipping
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getGroupId
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getHpkePrivateKey
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.getSignaturePrivateKey
import com.github.traderjoe95.mls.protocol.interop.util.getUInt
import com.github.traderjoe95.mls.protocol.interop.util.getULong
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.NodeIndex
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafIndices
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.tree.UpdatePath
import com.github.traderjoe95.mls.protocol.util.unsafe
import com.github.traderjoe95.mls.protocol.util.zipWithIndex
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextULong

@OptIn(ExperimentalStdlibApi::class)
data class TreeKemTestVector(
  val cipherSuite: CipherSuite,
  val groupId: GroupId,
  val epoch: ULong,
  val confirmedTranscriptHash: ByteArray,
  val ratchetTree: PublicRatchetTree,
  val leavesPrivate: List<LeafPrivate>,
  val updatePaths: List<UpdatePathEntry>,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getGroupId("group_id"),
    json.getULong("epoch"),
    json.getHexBinary("confirmed_transcript_hash"),
    PublicRatchetTree.decodeUnsafe(json.getHexBinary("ratchet_tree")),
    json.getJsonArray("leaves_private").map { LeafPrivate(it as JsonObject) },
    json.getJsonArray("update_paths").map { UpdatePathEntry(it as JsonObject) },
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/treekem.json",
    ): List<TreeKemTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { TreeKemTestVector(it as JsonObject) }

    fun generate(
      cipherSuite: CipherSuite,
      structure: TreeStructure,
    ): TreeKemTestVector {
      val groupId = GroupId.new()
      val epoch = Random.nextULong()
      val confirmedTranscriptHash = Random.nextBytes(cipherSuite.hashLen.toInt())
      val tree = structure.generateTree(cipherSuite, groupId)

      val leavesPrivate =
        tree.private
          .zipWithIndex()
          .zip(tree.signaturePrivateKeys) { (a, idx), b -> nullable { Triple(idx, a.bind(), b.bind()) } }
          .filterNotNull()
          .map { (idx, private, sig) ->
            val leafIdx = LeafIndex(idx.toUInt())
            val leafTree = tree[leafIdx]!!

            LeafPrivate(
              leafIdx,
              leafTree.getPrivateKey(leafIdx)!!,
              sig,
              private.pathSecrets.map { (node, secret) -> PathSecret(node, secret) },
            )
          }

      val updatePaths =
        tree.public.nonBlankLeafIndices.map { sender ->
          val senderTree = tree[sender]!!
          val groupContext =
            GroupContext(
              ProtocolVersion.MLS_1_0,
              cipherSuite,
              groupId,
              // Do this trick to make sure that the correct epoch is used in encryption
              epoch - 1U,
              tree.public.treeHash(cipherSuite),
              confirmedTranscriptHash,
            )

          val (updatedTree, updatePath, pathSecrets) =
            unsafe {
              createUpdatePath(
                senderTree,
                sender,
                setOf(),
                groupContext,
                tree.signaturePrivateKeys[sender.value.toInt()]!!,
              )
            }

          val fdp = senderTree.filteredDirectPath(sender)

          UpdatePathEntry(
            sender,
            updatePath,
            updatedTree.leafNodeIndices.map { it.leafIndex }.map { leaf ->
              if (leaf == sender || tree[leaf] == null) {
                null
              } else {
                val commonAncestorIdx = fdp.indexOfFirst { leaf.isInSubtreeOf(it) }
                pathSecrets[commonAncestorIdx]
              }
            },
            cipherSuite.deriveSecret(pathSecrets.last(), "path"),
            updatedTree.treeHash(cipherSuite),
          )
        }

      return TreeKemTestVector(
        cipherSuite,
        groupId,
        epoch,
        confirmedTranscriptHash,
        tree.public,
        leavesPrivate,
        updatePaths,
      )
    }

    fun allStructures(): List<TreeStructure> =
      listOf(
        // Full Trees
        FullTree(2U), FullTree(3U), FullTree(4U), FullTree(5U), FullTree(6U),
        FullTree(7U), FullTree(8U),
        // FullTree(8U) - 2U - 3U + new member
        InternalBlanksNoSkipping,
        // FullTree(8U) - 1U - 2U - 3U
        InternalBlanksWithSkipping,
        // FullTree(7U) + newMember
        UnmergedLeavesNoSkipping,
        // FullTree(1U) + 6 * new member - 5U + empty commit + new member
        UnmergedLeavesWithSkipping,
      )
  }

  data class LeafPrivate(
    val index: LeafIndex,
    val encryptionPriv: HpkePrivateKey,
    val signaturePriv: SignaturePrivateKey,
    val pathSecrets: List<PathSecret>,
  ) {
    constructor(json: JsonObject) : this(
      LeafIndex(json.getUInt("index")),
      json.getHpkePrivateKey("encryption_priv"),
      json.getSignaturePrivateKey("signature_priv"),
      json.getJsonArray("path_secrets").map { PathSecret(it as JsonObject) },
    )
  }

  data class PathSecret(
    val node: NodeIndex,
    val pathSecret: Secret,
  ) {
    constructor(json: JsonObject) : this(
      NodeIndex(json.getUInt("node")),
      json.getSecret("path_secret"),
    )
  }

  data class UpdatePathEntry(
    val sender: LeafIndex,
    val updatePath: UpdatePath,
    val pathSecrets: List<Secret?>,
    val commitSecret: Secret,
    val treeHashAfter: ByteArray,
  ) {
    constructor(json: JsonObject) : this(
      LeafIndex(json.getUInt("sender")),
      UpdatePath.decodeUnsafe(json.getHexBinary("update_path")),
      json.getJsonArray("path_secrets").map { (it as String?)?.hexToByteArray()?.asSecret },
      json.getSecret("commit_secret"),
      json.getHexBinary("tree_hash_after"),
    )
  }
}

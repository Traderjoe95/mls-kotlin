package com.github.traderjoe95.mls.protocol.interop.tree

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.FullTree
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.InternalBlanksNoSkipping
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure.InternalBlanksWithSkipping
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getGroupId
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.GroupId
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait

class TreeValidationTestVector(
  val cipherSuite: CipherSuite,
  val tree: PublicRatchetTree,
  val groupId: GroupId,
  val resolutions: List<List<UInt>>,
  val treeHashes: List<ByteArray>,
) {
  @OptIn(ExperimentalStdlibApi::class)
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    PublicRatchetTree.decodeUnsafe(json.getHexBinary("tree")),
    json.getGroupId("group_id"),
    json.getJsonArray("resolutions").map {
      when (it) {
        is Iterable<*> -> it.map { (it as Number).toLong().toUInt() }
        else -> error("Invalid type inside 'resolutions'")
      }
    },
    json.getJsonArray("tree_hashes").map { (it as String).hexToByteArray() },
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/tree-validation.json",
    ): List<TreeValidationTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { TreeValidationTestVector(it as JsonObject) }

    fun generate(
      cipherSuite: CipherSuite,
      treeStructure: TreeStructure,
    ): TreeValidationTestVector {
      val groupId = GroupId.new()
      val tree = treeStructure.generateTree(cipherSuite, groupId).public

      return TreeValidationTestVector(
        cipherSuite,
        tree,
        groupId,
        tree.indices.map { node -> tree.resolution(node).map { it.value } },
        tree.indices.map { node -> tree.treeHash(node, cipherSuite) },
      )
    }

    fun allStructures(): List<TreeStructure> =
      listOf(
        // Full Trees
        FullTree(2U), FullTree(3U), FullTree(4U), FullTree(5U), FullTree(6U),
        FullTree(7U), FullTree(8U), FullTree(32U), FullTree(33U), FullTree(34U),
        // FullTree(8U) - 2U - 3U + new member
        InternalBlanksNoSkipping,
        // FullTree(8U) - 1U - 2U - 3U
        InternalBlanksWithSkipping,
        // FullTree(7U) + newMember
        TreeStructure.UnmergedLeavesNoSkipping,
        // FullTree(1U) + 6 * new member - 5U + empty commit + new member
        TreeStructure.UnmergedLeavesWithSkipping,
      )
  }
}

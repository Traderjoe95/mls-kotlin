package com.github.traderjoe95.mls.protocol.interop.tree

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.choice
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getUInt
import com.github.traderjoe95.mls.protocol.interop.util.nextGroupContext
import com.github.traderjoe95.mls.protocol.interop.util.nextKeyPackage
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafIndices
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextUInt

data class TreeOperationsTestVector(
  val cipherSuite: CipherSuite,
  val treeBefore: ByteArray,
  val proposal: Proposal,
  val proposalSender: LeafIndex,
  val treeHashBefore: ByteArray,
  val treeAfter: ByteArray,
  val treeHashAfter: ByteArray,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getHexBinary("tree_before"),
    Proposal.decodeUnsafe(json.getHexBinary("proposal")),
    LeafIndex(json.getUInt("proposal_sender")),
    json.getHexBinary("tree_hash_before"),
    json.getHexBinary("tree_after"),
    json.getHexBinary("tree_hash_after"),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/tree-operations.json",
    ): List<TreeOperationsTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { TreeOperationsTestVector(it as JsonObject) }

    fun generate(
      cipherSuite: CipherSuite,
      scenario: Scenario,
    ): TreeOperationsTestVector {
      val treeBefore = generateTree(cipherSuite, scenario)
      val nonBlank = treeBefore.nonBlankLeafIndices

      val (proposal, sender) =
        when (scenario) {
          Scenario.AddRightFlank, Scenario.AddInternal, Scenario.AddExpand ->
            Add(Random.nextKeyPackage(cipherSuite).public) to Random.choice(nonBlank)

          Scenario.RemoveRightFlank, Scenario.RemoveTruncate ->
            Remove(nonBlank.last()) to Random.choice(nonBlank.dropLast(1))

          Scenario.RemoveInternal ->
            Remove(Random.choice(nonBlank.dropLast(1))).let { remove ->
              remove to Random.choice(nonBlank.filter { it neq remove.removed })
            }

          Scenario.Update ->
            Random.choice(nonBlank).let { leaf ->
              Update(
                LeafNode.update(
                  cipherSuite,
                  cipherSuite.generateHpkeKeyPair().public,
                  treeBefore.leafNode(leaf),
                  leaf,
                  GroupId.new(),
                  cipherSuite.generateSignatureKeyPair().private,
                ),
              ) to leaf
            }
        }

      val treeAfter =
        when (proposal) {
          is Add -> treeBefore.insert(proposal.keyPackage.leafNode).first
          is Update -> treeBefore.update(sender, proposal.leafNode)
          is Remove -> treeBefore.remove(proposal.removed)
          else -> error("unreachable")
        }

      return TreeOperationsTestVector(
        cipherSuite,
        treeBefore.encodeUnsafe(),
        proposal,
        sender,
        treeBefore.treeHash(cipherSuite),
        treeAfter.encodeUnsafe(),
        treeAfter.treeHash(cipherSuite),
      )
    }

    internal fun generateTree(
      cipherSuite: CipherSuite,
      scenario: Scenario,
    ): PublicRatchetTree =
      when (scenario) {
        Scenario.AddRightFlank ->
          generateFullTree(cipherSuite, Random.nextUInt(5U..7U)).first

        Scenario.AddInternal -> {
          val lastLeaf = Random.nextUInt(5U..7U)
          val internalBlank = Random.nextUInt(2U..<lastLeaf)

          generateFullTree(cipherSuite, Random.nextUInt(5U..7U)).first.remove(LeafIndex(internalBlank))
        }

        Scenario.AddExpand ->
          generateFullTree(cipherSuite, 8U).first

        Scenario.Update ->
          generateFullTree(cipherSuite, Random.nextUInt(5U..8U)).first

        Scenario.RemoveRightFlank ->
          generateFullTree(cipherSuite, Random.nextUInt(6U..8U)).first

        Scenario.RemoveInternal ->
          generateFullTree(cipherSuite, Random.nextUInt(6U..8U)).first

        Scenario.RemoveTruncate ->
          generateFullTree(cipherSuite, 5U).first
      }.public

    internal fun generateFullTree(
      cipherSuite: CipherSuite,
      leafCount: UInt,
      groupId: GroupId? = null,
    ): Pair<RatchetTree, MutableList<KeyPackage.Private>> {
      val firstMember = Random.nextKeyPackage(cipherSuite)
      val allMembers = mutableListOf(firstMember)
      var tree = RatchetTree.new(firstMember)
      var groupContext = Random.nextGroupContext(cipherSuite, groupId = groupId)

      for (i in 1U..<leafCount) {
        val newMember = Random.nextKeyPackage(cipherSuite)

        val (newTree, newIndex) = tree.insert(newMember.leafNode)

        val (updatedTree, _, _) =
          unsafe {
            createUpdatePath(
              newTree,
              LeafIndex(i - 1U),
              setOf(newIndex),
              groupContext,
              allMembers.last().signaturePrivateKey,
            )
          }

        allMembers.add(newMember.copy(encPrivateKey = updatedTree.getPrivateKey(LeafIndex(i - 1U))!!))
        tree = updatedTree
        groupContext = groupContext.copy(epoch = groupContext.epoch + 1U)
      }

      return tree to allMembers
    }
  }

  enum class Scenario {
    AddRightFlank,
    AddInternal,
    AddExpand,
    Update,
    RemoveRightFlank,
    RemoveInternal,
    RemoveTruncate,
  }
}

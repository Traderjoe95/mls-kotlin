package com.github.traderjoe95.mls.protocol.interop.tree

import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.nextGroupContext
import com.github.traderjoe95.mls.protocol.interop.util.nextKeyPackage
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.PrivateRatchetTree
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.join
import com.github.traderjoe95.mls.protocol.tree.createUpdatePath
import com.github.traderjoe95.mls.protocol.tree.nonBlankLeafIndices
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.util.unsafe
import kotlin.random.Random

sealed interface TreeStructure {
  fun generateTree(
    cipherSuite: CipherSuite,
    groupId: GroupId,
  ): TestTree

  data class FullTree(val leaves: UInt) : TreeStructure {
    override fun generateTree(
      cipherSuite: CipherSuite,
      groupId: GroupId,
    ): TestTree = TestTree.full(cipherSuite, groupId, leaves)
  }

  data object InternalBlanksNoSkipping : TreeStructure {
    override fun generateTree(
      cipherSuite: CipherSuite,
      groupId: GroupId,
    ): TestTree =
      TestTree
        .full(cipherSuite, groupId, 8U)
        .removeMembersAndAddNew(listOf(2U, 3U), LeafIndex(0U))
  }

  data object InternalBlanksWithSkipping : TreeStructure {
    override fun generateTree(
      cipherSuite: CipherSuite,
      groupId: GroupId,
    ): TestTree =
      TestTree
        .full(cipherSuite, groupId, 8U)
        .removeMembers(listOf(1U, 2U, 3U), LeafIndex(0U))
  }

  data object UnmergedLeavesNoSkipping : TreeStructure {
    override fun generateTree(
      cipherSuite: CipherSuite,
      groupId: GroupId,
    ): TestTree =
      TestTree
        .full(cipherSuite, groupId, 7U)
        .addMember(LeafIndex(0U), updatePath = false)
  }

  data object UnmergedLeavesWithSkipping : TreeStructure {
    override fun generateTree(
      cipherSuite: CipherSuite,
      groupId: GroupId,
    ): TestTree =
      TestTree.new(cipherSuite, groupId)
        .addMember(LeafIndex(0U), updatePath = false)
        .addMember(LeafIndex(0U), updatePath = false)
        .addMember(LeafIndex(0U), updatePath = false)
        .addMember(LeafIndex(0U), updatePath = false)
        .addMember(LeafIndex(0U), updatePath = false)
        .addMember(LeafIndex(0U), updatePath = false)
        .removeMembers(listOf(5U), LeafIndex(0U))
        .updatePath(LeafIndex(4U))
        .addMember(LeafIndex(0U), updatePath = false)
  }
}

data class TestTree(
  val cipherSuite: CipherSuite,
  val groupId: GroupId,
  val public: PublicRatchetTree,
  val private: List<PrivateRatchetTree?>,
  val signaturePrivateKeys: List<SignaturePrivateKey?>,
) {
  operator fun get(index: UInt): RatchetTree? = private.getOrNull(index.toInt())?.let { RatchetTree(cipherSuite, public, it) }

  operator fun get(index: LeafIndex): RatchetTree? = this[index.value]

  fun addMember(
    committer: LeafIndex,
    updatePath: Boolean = true,
  ): TestTree {
    val newMember = Random.nextKeyPackage(cipherSuite)

    val (newPublic, newLeaf) = public.insert(newMember.leafNode)

    return copy(
      public = newPublic,
      private = private.replace(newLeaf, newPublic.join(cipherSuite, newLeaf, newMember.encPrivateKey).private),
      signaturePrivateKeys = signaturePrivateKeys.replace(newLeaf, newMember.signaturePrivateKey),
    ).let {
      if (updatePath) {
        it.updatePath(committer, setOf(newLeaf))
      } else {
        it
      }
    }
  }

  fun removeMembers(
    removed: List<UInt>,
    committer: LeafIndex,
  ): TestTree =
    copy(
      public = public.remove(removed.map(::LeafIndex)),
      private = private.filterIndices(removed.toSet()),
      signaturePrivateKeys = signaturePrivateKeys.filterIndices(removed.toSet()),
    ).updatePath(committer)

  fun removeMembersAndAddNew(
    removed: List<UInt>,
    committer: LeafIndex,
  ): TestTree {
    val newMember = Random.nextKeyPackage(cipherSuite)

    val newPublic = public.remove(removed.map(::LeafIndex))
    val newPrivate = private.filterIndices(removed.toSet())
    val newSig = signaturePrivateKeys.filterIndices(removed.toSet())

    val (publicAfterInsert, newLeaf) = newPublic.insert(newMember.leafNode)

    return copy(
      public = publicAfterInsert,
      private = newPrivate.replace(newLeaf, newPublic.join(cipherSuite, newLeaf, newMember.encPrivateKey).private),
      signaturePrivateKeys = newSig.replace(newLeaf, newMember.signaturePrivateKey),
    ).updatePath(committer, setOf(newLeaf))
  }

  fun updatePath(
    committer: LeafIndex,
    newLeaves: Set<LeafIndex> = setOf(),
  ): TestTree {
    val (updatedTreeSender, _, pathSecrets) =
      unsafe {
        createUpdatePath(
          RatchetTree(cipherSuite, public, private[committer]!!),
          committer,
          newLeaves,
          Random.nextGroupContext(cipherSuite, groupId),
          signaturePrivateKeys[committer]!!,
        )
      }

    val newPublic = updatedTreeSender.public
    var newPrivate = private.replace(committer, updatedTreeSender.private)

    val fdp = newPublic.filteredDirectPath(committer)
    // Inject path secrets for all other members
    newPublic.nonBlankLeafIndices
      .filter { it neq committer }
      .forEach { leaf ->
        val commonAncestorIdx = fdp.indexOfFirst { leaf.isInSubtreeOf(it.first) }
        val commonAncestor = fdp[commonAncestorIdx].first
        val secret = pathSecrets[commonAncestorIdx]

        newPrivate = newPrivate.replace(leaf, this[leaf]!!.insertPathSecrets(commonAncestor, secret).private)
      }

    return copy(public = newPublic, private = newPrivate)
  }

  private fun <T : Any> List<T?>.filterIndices(indices: Set<UInt>): List<T?> =
    mapIndexed { idx, t -> t.takeUnless { idx.toUInt() in indices } }

  private fun <T : Any> List<T?>.replace(
    index: UInt,
    value: T?,
  ): List<T?> = ensureMinSize(index + 1U).mapIndexed { idx, t -> if (idx.toUInt() == index) value else t }

  private fun <T : Any> List<T?>.replace(
    index: LeafIndex,
    value: T?,
  ): List<T?> = replace(index.value, value)

  private operator fun <T : Any> List<T?>.get(index: UInt): T? = this[index.toInt()]

  private operator fun <T : Any> List<T?>.get(index: LeafIndex): T? = this[index.value]

  private fun <T : Any> List<T?>.ensureMinSize(minSize: UInt): List<T?> =
    if (uSize >= minSize) {
      this
    } else {
      List(minSize.toInt()) { if (it < size) this[it] else null }
    }

  companion object {
    fun new(
      cipherSuite: CipherSuite,
      groupId: GroupId,
    ): TestTree {
      val firstMember = Random.nextKeyPackage(cipherSuite)
      val tree = RatchetTree.new(firstMember)

      return TestTree(
        cipherSuite,
        groupId,
        tree.public,
        listOf(tree.private),
        listOf(firstMember.signaturePrivateKey),
      )
    }

    fun full(
      cipherSuite: CipherSuite,
      groupId: GroupId,
      leaves: UInt,
    ): TestTree {
      var tree = new(cipherSuite, groupId)

      for (l in 1U..<leaves) {
        tree = tree.addMember(LeafIndex(l - 1U), updatePath = true)
      }

      return tree
    }
  }
}

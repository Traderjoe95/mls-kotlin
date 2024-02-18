package com.github.traderjoe95.mls.protocol.group

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.crypto.KeyScheduleImpl
import com.github.traderjoe95.mls.protocol.group.GroupContext.InterimTranscriptHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.newTree
import com.github.traderjoe95.mls.protocol.tree.TreePrivateKeyStore
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode

internal data class GroupEpoch(
  val epoch: ULong,
  val tree: RatchetTree,
  val keySchedule: KeySchedule,
  val confirmedTranscriptHash: ByteArray,
  val extensions: GroupContextExtensions,
  val interimTranscriptHash: ByteArray,
  val initiatingCommit: Commit,
  val confirmationTag: Mac,
  val treePrivateKeyStore: TreePrivateKeyStore,
  internal val proposals: MutableMap<Int, Pair<Proposal, LeafIndex?>> = mutableMapOf(),
) {
  companion object {
    fun init(
      keyPackage: KeyPackage,
      hpkeKeyPair: HpkeKeyPair,
      vararg extensions: GroupContextExtension<*>,
    ): GroupEpoch =
      init(
        keyPackage.cipherSuite,
        keyPackage.leafNode,
        hpkeKeyPair.private,
        *extensions,
      )

    fun init(
      cipherSuite: CipherSuite,
      leafNode: KeyPackageLeafNode,
      decryptionKey: HpkePrivateKey,
      vararg extensions: GroupContextExtension<*>,
    ): GroupEpoch {
      val keySchedule = KeyScheduleImpl.new(cipherSuite)

      return GroupEpoch(
        0UL,
        leafNode.newTree(),
        keySchedule,
        byteArrayOf(),
        extensions.toList(),
        cipherSuite.hash(
          GroupContext.InterimTranscriptHashInput(
            cipherSuite.mac(keySchedule.confirmationKey, byteArrayOf()),
          ).encodeUnsafe(),
        ),
        Commit.empty,
        cipherSuite.mac(keySchedule.confirmationKey, byteArrayOf()),
        TreePrivateKeyStore.init(leafNode.encryptionKey, decryptionKey),
      )
    }

    context(ICipherSuite)
    fun from(
      groupContext: GroupContext,
      tree: RatchetTree,
      keySchedule: KeySchedule,
      commit: Commit,
      privateKeyStore: TreePrivateKeyStore,
    ): GroupEpoch =
      GroupEpoch(
        groupContext.epoch,
        tree,
        keySchedule,
        groupContext.confirmedTranscriptHash,
        groupContext.extensions,
        groupContext.interimTranscriptHash,
        commit,
        mac(keySchedule.confirmationKey, groupContext.confirmedTranscriptHash),
        privateKeyStore,
      )
  }
}

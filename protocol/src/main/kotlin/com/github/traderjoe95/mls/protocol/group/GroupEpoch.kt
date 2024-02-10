package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.crypto.KeyScheduleImpl
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.tree.LeafNodeRecord
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.RatchetTree.Companion.newTree
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode

data class GroupEpoch(
  val epoch: ULong,
  val tree: RatchetTree,
  val keySchedule: KeySchedule,
  val confirmedTranscriptHash: ByteArray,
  val extensions: GroupContextExtensions,
  val interimTranscriptHash: ByteArray = byteArrayOf(),
  val initiatingCommit: Commit,
  internal val proposals: MutableMap<Int, Pair<Proposal, UInt?>> = mutableMapOf(),
) {
  companion object {
    context(Raise<EncoderError>)
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

    context(Raise<EncoderError>)
    fun init(
      cipherSuite: CipherSuite,
      leafNode: KeyPackageLeafNode,
      decryptionKey: HpkePrivateKey,
      vararg extensions: GroupContextExtension<*>,
    ): GroupEpoch {
      val keySchedule = KeyScheduleImpl.new(cipherSuite)

      return GroupEpoch(
        0UL,
        LeafNodeRecord(leafNode to decryptionKey).newTree(),
        keySchedule,
        byteArrayOf(),
        extensions.toList(),
        cipherSuite.hash(
          EncoderError.wrap {
            GroupContext.InterimTranscriptHashInput.T.encode(
              GroupContext.InterimTranscriptHashInput(
                cipherSuite.mac(keySchedule.confirmationKey, byteArrayOf()),
              ),
            )
          },
        ),
        Commit.empty,
      )
    }
  }
}

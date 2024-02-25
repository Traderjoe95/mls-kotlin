package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.GroupContextUpdateError
import com.github.traderjoe95.mls.protocol.group.GroupContext.ConfirmedTranscriptHashInput
import com.github.traderjoe95.mls.protocol.group.GroupContext.ConfirmedTranscriptHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.group.GroupContext.InterimTranscriptHashInput
import com.github.traderjoe95.mls.protocol.group.GroupContext.InterimTranscriptHashInput.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

context(Raise<GroupContextUpdateError>)
internal fun GroupContext.evolve(
  wireFormat: WireFormat,
  framedContent: FramedContent<Commit>,
  signature: Signature,
  newTree: RatchetTree,
  newExtensions: List<GroupContextExtension<*>>? = null,
): GroupContext {
  val newConfirmedTranscriptHash =
    updateConfirmedTranscriptHash(cipherSuite, interimTranscriptHash, wireFormat, framedContent, signature)

  return GroupContext(
    protocolVersion,
    cipherSuite,
    groupId,
    epoch + 1U,
    newTree.treeHash,
    newConfirmedTranscriptHash,
    newExtensions ?: extensions,
  )
}

internal fun updateConfirmedTranscriptHash(
  cipherSuite: ICipherSuite,
  interimTranscriptHash: ByteArray,
  wireFormat: WireFormat,
  framedContent: FramedContent<Commit>,
  signature: Signature,
): ByteArray =
  cipherSuite.hash(
    interimTranscriptHash +
      ConfirmedTranscriptHashInput(
        wireFormat,
        framedContent,
        signature,
      ).encodeUnsafe(),
  )

internal fun updateInterimTranscriptHash(
  cipherSuite: ICipherSuite,
  confirmedTranscriptHash: ByteArray,
  confirmationTag: Mac,
): ByteArray = cipherSuite.hash(confirmedTranscriptHash + InterimTranscriptHashInput(confirmationTag).encodeUnsafe())

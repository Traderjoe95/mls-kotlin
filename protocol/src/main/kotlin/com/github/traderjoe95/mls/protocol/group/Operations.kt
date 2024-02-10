package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.GroupContextUpdateError
import com.github.traderjoe95.mls.protocol.group.GroupContext.ConfirmedTranscriptHashInput
import com.github.traderjoe95.mls.protocol.tree.RatchetTree
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupContextExtension
import com.github.traderjoe95.mls.protocol.types.RatchetTreeExt
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

context(Raise<BaseEncoderError>)
fun GroupState.createGroupInfo(
  confirmationTag: Mac,
  public: Boolean,
): GroupInfo =
  GroupInfo.create(
    groupContext,
    listOfNotNull(
      RatchetTreeExt(tree),
      if (public) ExternalPub(deriveKeyPair(keySchedule.externalSecret).public) else null,
      *Extension.grease(),
    ),
    confirmationTag,
  )

context(ICipherSuite, Raise<GroupContextUpdateError>)
internal fun GroupContext.evolve(
  wireFormat: WireFormat,
  framedContent: FramedContent<Commit>,
  signature: Signature,
  newTree: RatchetTree,
  newExtensions: List<GroupContextExtension<*>> = extensions,
): GroupContext {
  val newConfirmedTranscriptHash =
    hash(
      interimTranscriptHash +
        EncoderError.wrap {
          ConfirmedTranscriptHashInput.T.encode(
            ConfirmedTranscriptHashInput(wireFormat, framedContent, signature),
          )
        },
    )

  return GroupContext(
    protocolVersion,
    cipherSuite,
    groupId,
    epoch + 1U,
    EncoderError.wrap { newTree.treeHash },
    newConfirmedTranscriptHash,
    newExtensions,
  )
}

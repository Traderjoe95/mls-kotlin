package com.github.traderjoe95.mls.protocol.message

import arrow.core.Either
import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.error.CreateMessageError
import com.github.traderjoe95.mls.protocol.error.NewMemberAddProposalError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.checkSupport
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

object Messages {
  @JvmStatic
  fun externalProposalMessage(
    proposal: Proposal,
    groupContext: GroupContext,
    senderIndex: UInt,
    signaturePrivateKey: SignaturePrivateKey,
    authenticatedData: ByteArray = byteArrayOf(),
  ): Either<CreateMessageError, MlsMessage<PublicMessage<Proposal>>> =
    either {
      val framedContent = FramedContent.createExternalProposal(proposal, senderIndex, groupContext, authenticatedData)
      val signature =
        framedContent.sign(WireFormat.MlsPublicMessage, groupContext, signaturePrivateKey).bind()

      MlsMessage.public(
        PublicMessage.create(
          AuthenticatedContent(WireFormat.MlsPublicMessage, framedContent, signature, null),
          groupContext,
          null,
        ),
      )
    }

  @JvmStatic
  fun newMemberProposalMessage(
    keyPackage: KeyPackage.Private,
    groupContext: GroupContext,
    authenticatedData: ByteArray = byteArrayOf(),
  ): Either<NewMemberAddProposalError, MlsMessage<PublicMessage<Proposal>>> =
    either {
      keyPackage.leafNode.checkSupport(groupContext.extensions, LeafIndex(0U))

      val framedContent = FramedContent.createNewMemberProposal(Add(keyPackage.public), groupContext, authenticatedData)
      val signature = framedContent.sign(WireFormat.MlsPublicMessage, groupContext, keyPackage.signaturePrivateKey).bind()

      MlsMessage.public(
        PublicMessage.create(
          AuthenticatedContent(WireFormat.MlsPublicMessage, framedContent, signature, null),
          groupContext,
          null,
        ),
      )
    }
}

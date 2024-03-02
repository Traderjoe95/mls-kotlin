package com.github.traderjoe95.mls.protocol.message

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.Struct4
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.error.MessageSenderError.InvalidSenderType
import com.github.traderjoe95.mls.protocol.error.PublicMessageError
import com.github.traderjoe95.mls.protocol.error.PublicMessageRecipientError
import com.github.traderjoe95.mls.protocol.error.PublicMessageSenderError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent.Tbm.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType.NewMemberCommit
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType.NewMemberProposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class PublicMessage<out C : Content<C>>(
  private val content: FramedContent<C>,
  val signature: Signature,
  val confirmationTag: Mac?,
  val membershipTag: Mac?,
) : GroupMessage<C>, Struct4T.Shape<FramedContent<C>, Signature, Mac?, Mac?> {
  constructor(authContent: AuthenticatedContent<C>, membershipTag: Mac?) : this(
    authContent.content,
    authContent.signature,
    authContent.confirmationTag,
    membershipTag,
  )

  override val groupId: GroupId
    get() = content.groupId
  override val epoch: ULong
    get() = content.epoch
  override val contentType: ContentType<C>
    get() = content.contentType

  private val authenticatedContent: AuthenticatedContent<C>
    get() = AuthenticatedContent(WireFormat.MlsPublicMessage, content, signature, confirmationTag)

  override suspend fun unprotect(groupState: GroupState.Active): Either<PublicMessageRecipientError, AuthenticatedContent<C>> =
    either {
      unprotect(
        groupState.groupContext,
        groupState.keySchedule.membershipKey,
        groupState.tree.getSignaturePublicKey(groupState.groupContext, content),
      ).bind()
    }

  internal fun unprotect(
    groupContext: GroupContext,
    membershipKey: Secret,
    signaturePublicKey: SignaturePublicKey,
  ): Either<PublicMessageRecipientError, AuthenticatedContent<C>> =
    either {
      if (content.contentType == ContentType.Application) raise(PublicMessageError.ApplicationMessageMustNotBePublic)

      if (content.sender.type == SenderType.Member) {
        groupContext.cipherSuite.verifyMac(
          membershipKey,
          authenticatedContent.tbm(groupContext).encodeUnsafe(),
          membershipTag!!,
        )
      }

      authenticatedContent.apply { verify(groupContext, signaturePublicKey) }
    }

  companion object : Encodable<PublicMessage<*>> {
    override val dataT: DataType<PublicMessage<*>> =
      throwAnyError {
        struct("PublicMessage") {
          it.field("content", FramedContent.dataT)
            .field("signature", Signature.dataT)
            .select<Mac?, _>(ContentType.T, "content", "content_type") {
              case(ContentType.Commit).then(Mac.dataT, "confirmation_tag")
                .orElseNothing()
            }
            .select<Mac?, _>(SenderType.T, "content", "sender", "sender_type") {
              case(SenderType.Member).then(Mac.dataT, "membership_tag")
                .orElseNothing()
            }
        }.lift(
          up = { content, signature, confirmationTag, membershipTag ->
            PublicMessage<Content<*>>(
              content,
              signature,
              confirmationTag,
              membershipTag,
            )
          },
          down = { message ->
            Struct4(
              message.content,
              message.signature,
              message.confirmationTag,
              message.membershipTag,
            )
          },
        )
      }

    context(Raise<PublicMessageSenderError>)
    fun <C : Content<C>> create(
      content: AuthenticatedContent<C>,
      groupContext: GroupContext,
      membershipKey: Secret,
    ): PublicMessage<C> {
      if (content.contentType == ContentType.Application) raise(PublicMessageError.ApplicationMessageMustNotBePublic)

      val inner = content.content.content

      if (content.senderType == NewMemberCommit && inner !is Commit) {
        raise(
          InvalidSenderType(
            content.senderType,
            "Content type must be 'Commit', but got ${content.contentType}",
          ),
        )
      }

      if (content.senderType == NewMemberProposal && inner !is Proposal) {
        raise(
          InvalidSenderType(
            content.senderType,
            "Content type must be 'Proposal', but got ${content.contentType}",
          ),
        )
      } else if (content.senderType == NewMemberProposal && inner is Proposal && inner.type != ProposalType.Add) {
        raise(
          InvalidSenderType(
            content.senderType,
            "Proposal type must be 'Add', but got ${inner.type}",
          ),
        )
      }

      val membershipTag: Mac? =
        if (content.content.sender.type == SenderType.Member) {
          groupContext.cipherSuite.mac(membershipKey, content.tbm(groupContext).encodeUnsafe())
        } else {
          null
        }

      return PublicMessage(content, membershipTag)
    }
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as PublicMessage<*>

    if (content != other.content) return false
    if (!signature.bytes.contentEquals(other.signature.bytes)) return false
    if (confirmationTag != null) {
      return other.confirmationTag == null || !confirmationTag.bytes.contentEquals(other.confirmationTag.bytes)
    } else if (other.confirmationTag != null) {
      return false
    }
    if (membershipTag != null) {
      return other.membershipTag == null || !membershipTag.bytes.contentEquals(other.membershipTag.bytes)
    } else if (other.membershipTag != null) {
      return false
    }

    return true
  }

  override fun hashCode(): Int {
    var result = content.hashCode()
    result = 31 * result + signature.bytes.contentHashCode()
    result = 31 * result + (confirmationTag?.bytes?.contentHashCode() ?: 0)
    result = 31 * result + (membershipTag?.bytes?.contentHashCode() ?: 0)
    return result
  }
}

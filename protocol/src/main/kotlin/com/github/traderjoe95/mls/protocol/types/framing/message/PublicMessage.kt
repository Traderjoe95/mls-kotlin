package com.github.traderjoe95.mls.protocol.types.framing.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Struct4
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.MessageSenderError.InvalidSenderType
import com.github.traderjoe95.mls.protocol.error.PublicMessageRecipientError
import com.github.traderjoe95.mls.protocol.error.PublicMessageSenderError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.ProposalType
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType.NewMemberCommit
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType.NewMemberProposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import de.traderjoe.ulid.ULID

data class PublicMessage<C : Content>(
  private val content: FramedContent<C>,
  val signature: Signature,
  val confirmationTag: Mac?,
  val membershipTag: Mac?,
) : GroupMessage<PublicMessageRecipientError>, Struct4T.Shape<FramedContent<C>, Signature, Mac?, Mac?> {
  constructor(authContent: AuthenticatedContent<C>, membershipTag: Mac?) : this(
    authContent.content,
    authContent.signature,
    authContent.confirmationTag,
    membershipTag,
  )

  override val groupId: ULID
    get() = content.groupId
  override val epoch: ULong
    get() = content.epoch
  override val contentType: ContentType
    get() = content.contentType

  val authenticatedContent: AuthenticatedContent<C>
    get() = AuthenticatedContent(WireFormat.MlsPublicMessage, content, signature, confirmationTag)

  context(GroupState, Raise<PublicMessageRecipientError>)
  override suspend fun getAuthenticatedContent(): AuthenticatedContent<*> =
    EncoderError.wrap {
      val groupContext = groupContext(content.epoch)

      if (content.sender.type == SenderType.Member) {
        verifyMac(
          keySchedule(content.epoch).membershipKey,
          AuthenticatedContent.Tbm.T.encode(authenticatedContent.tbm(groupContext)),
          membershipTag!!,
        )
      }

      authenticatedContent.apply { verify(groupContext) }
    }

  companion object {
    val T: DataType<PublicMessage<*>> =
      throwAnyError {
        struct("PublicMessage") {
          it.field("content", FramedContent.T)
            .field("signature", Signature.T)
            .select<Mac?, _>(ContentType.T, "content", "content_type") {
              case(ContentType.Commit).then(Mac.T, "confirmation_tag")
                .orElseNothing()
            }
            .select<Mac?, _>(SenderType.T, "content", "sender", "sender_type") {
              case(SenderType.Member).then(Mac.T, "membership_tag")
                .orElseNothing()
            }
        }.lift(
          up = { content, signature, confirmationTag, membershipTag ->
            PublicMessage(
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

    context(GroupState, Raise<PublicMessageSenderError>)
    fun <C : Content> create(
      authContent: AuthenticatedContent<C>,
    ): PublicMessage<C> =
      with(cipherSuite) {
        with(keySchedule) { create(authContent, groupContext) }
      }

    context(ICipherSuite, KeySchedule, Raise<PublicMessageSenderError>)
    fun <C : Content> create(
      content: AuthenticatedContent<C>,
      groupContext: GroupContext,
    ): PublicMessage<C> {
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
          mac(
            membershipKey,
            EncoderError.wrap { AuthenticatedContent.Tbm.T.encode(content.tbm(groupContext)) },
          )
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
    if (!signature.value.contentEquals(other.signature.value)) return false
    if (confirmationTag != null) {
      return other.confirmationTag == null || !confirmationTag.value.contentEquals(other.confirmationTag.value)
    } else if (other.confirmationTag != null) {
      return false
    }
    if (membershipTag != null) {
      return other.membershipTag == null || !membershipTag.value.contentEquals(other.membershipTag.value)
    } else if (other.membershipTag != null) {
      return false
    }

    return true
  }

  override fun hashCode(): Int {
    var result = content.hashCode()
    result = 31 * result + signature.value.contentHashCode()
    result = 31 * result + (confirmationTag?.value?.contentHashCode() ?: 0)
    result = 31 * result + (membershipTag?.value?.contentHashCode() ?: 0)
    return result
  }
}

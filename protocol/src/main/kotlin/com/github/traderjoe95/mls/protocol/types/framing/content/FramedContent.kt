package com.github.traderjoe95.mls.protocol.types.framing.content

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.Struct6T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint64
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.MacError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.T
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import de.traderjoe.ulid.ULID

data class FramedContent<out T : Content>(
  val groupId: ULID,
  val epoch: ULong,
  val sender: Sender,
  val authenticatedData: ByteArray,
  val contentType: ContentType,
  val content: T,
) : Struct6T.Shape<ULID, ULong, Sender, ByteArray, ContentType, Content> {
  constructor(groupId: ULID, epoch: ULong, sender: Sender, authenticatedData: ByteArray, content: T) : this(
    groupId,
    epoch,
    sender,
    authenticatedData,
    content.contentType,
    content,
  )

  companion object {
    val T: DataType<FramedContent<*>> =
      throwAnyError {
        struct("FramedContent") {
          it.field("group_id", ULID.T)
            .field("epoch", uint64.asULong)
            .field("sender", Sender.T)
            .field("authenticated_data", opaque[V])
            .field("content_type", ContentType.T)
            .select<Content, _>(ContentType.T, "content_type") {
              case(ContentType.Application).then(ApplicationData.T, "application_data")
                .case(ContentType.Proposal).then(Proposal.T, "proposal")
                .case(ContentType.Commit).then(Commit.T, "commit")
            }
        }.lift(::FramedContent)
      }
  }

  fun tbs(
    wireFormat: WireFormat,
    groupContext: GroupContext?,
  ): Tbs =
    Tbs(
      ProtocolVersion.MLS_1_0,
      wireFormat,
      this,
      groupContext,
    )

  context(GroupState, Raise<EncoderError>)
  fun sign(
    wireFormat: WireFormat,
    groupContext: GroupContext,
  ): Signature = sign(wireFormat, groupContext, signingKey)

  context(ICipherSuite, Raise<EncoderError>)
  fun sign(
    wireFormat: WireFormat,
    groupContext: GroupContext,
    signingKey: SigningKey,
  ): Signature =
    EncoderError.wrap {
      signWithLabel(
        signingKey,
        "FramedContentTBS",
        Tbs.T.encode(tbs(wireFormat, groupContext)),
      )
    }

  context(GroupState, Raise<SignatureError>, Raise<MacError>, Raise<EpochError>)
  fun verifySignature(
    authData: AuthData,
    wireFormat: WireFormat,
    groupContext: GroupContext,
  ) = EncoderError.wrap {
    val tbs = tbs(wireFormat, groupContext)
    verifyWithLabel(
      getVerificationKey(this@FramedContent),
      "FramedContentTBS",
      Tbs.T.encode(tbs),
      authData.signature,
    )
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as FramedContent<*>

    if (groupId != other.groupId) return false
    if (epoch != other.epoch) return false
    if (sender != other.sender) return false
    if (!authenticatedData.contentEquals(other.authenticatedData)) return false
    if (contentType != other.contentType) return false
    if (content != other.content) return false

    return true
  }

  override fun hashCode(): Int {
    var result = groupId.hashCode()
    result = 31 * result + epoch.hashCode()
    result = 31 * result + sender.hashCode()
    result = 31 * result + authenticatedData.contentHashCode()
    result = 31 * result + contentType.hashCode()
    result = 31 * result + content.hashCode()
    return result
  }

  data class Tbs(
    val version: ProtocolVersion,
    val wireFormat: WireFormat,
    val content: FramedContent<*>,
    val groupContext: GroupContext?,
  ) : Struct4T.Shape<ProtocolVersion, WireFormat, FramedContent<*>, GroupContext?> {
    companion object {
      val T: DataType<Tbs> =
        throwAnyError {
          struct("FramedContentTBS") {
            it.field("version", ProtocolVersion.T, ProtocolVersion.MLS_1_0)
              .field("wire_format", WireFormat.T)
              .field("content", FramedContent.T)
              .select<GroupContext?, _>(SenderType.T, "content", "sender", "sender_type") {
                case(SenderType.Member, SenderType.NewMemberCommit).then(GroupContext.T, "context")
                  .orElseNothing()
              }
          }.lift(::Tbs)
        }

      fun create(
        wireFormat: WireFormat,
        content: FramedContent<*>,
        groupContext: GroupContext?,
      ): Tbs = Tbs(ProtocolVersion.MLS_1_0, wireFormat, content, groupContext)
    }
  }

  data class AuthData(val signature: Signature, val confirmationTag: Mac?)
}

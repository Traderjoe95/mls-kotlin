package com.github.traderjoe95.mls.protocol.types.framing.content

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
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
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.MacError
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent.Tbs.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class FramedContent<out T : Content>(
  val groupId: GroupId,
  val epoch: ULong,
  val sender: Sender,
  val authenticatedData: ByteArray,
  val contentType: ContentType,
  val content: T,
) : Struct6T.Shape<GroupId, ULong, Sender, ByteArray, ContentType, Content> {
  constructor(groupId: GroupId, epoch: ULong, sender: Sender, authenticatedData: ByteArray, content: T) : this(
    groupId,
    epoch,
    sender,
    authenticatedData,
    content.contentType,
    content,
  )

  companion object : Encodable<FramedContent<*>> {
    override val dataT: DataType<FramedContent<*>> =
      throwAnyError {
        struct("FramedContent") {
          it.field("group_id", GroupId.dataT)
            .field("epoch", uint64.asULong)
            .field("sender", Sender.dataT)
            .field("authenticated_data", opaque[V])
            .field("content_type", ContentType.T)
            .select<Content, _>(ContentType.T, "content_type") {
              case(ContentType.Application).then(ApplicationData.dataT, "application_data")
                .case(ContentType.Proposal).then(Proposal.dataT, "proposal")
                .case(ContentType.Commit).then(Commit.dataT, "commit")
            }
        }.lift(::FramedContent)
      }

    fun <C : Content> createMember(
      groupContext: GroupContext,
      content: C,
      leafIndex: LeafIndex,
      authenticatedData: ByteArray = byteArrayOf(),
    ): FramedContent<C> =
      FramedContent(
        groupContext.groupId,
        groupContext.epoch,
        Sender.member(leafIndex),
        authenticatedData,
        content,
      )
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

  context(GroupState, Raise<SenderCommitError>)
  fun sign(
    wireFormat: WireFormat,
    groupContext: GroupContext,
  ): Signature = ensureActive { sign(cipherSuite, wireFormat, groupContext, signaturePrivateKey) }

  fun sign(
    cipherSuite: ICipherSuite,
    wireFormat: WireFormat,
    groupContext: GroupContext,
    signaturePrivateKey: SignaturePrivateKey,
  ): Signature =
    cipherSuite.signWithLabel(
      signaturePrivateKey,
      "FramedContentTBS",
      tbs(wireFormat, groupContext).encodeUnsafe(),
    )

  context(Raise<SignatureError>, Raise<MacError>, Raise<EpochError>)
  fun verifySignature(
    authData: AuthData,
    wireFormat: WireFormat,
    groupContext: GroupContext,
    signaturePublicKey: SignaturePublicKey,
  ) = groupContext.cipherSuite.verifyWithLabel(
    signaturePublicKey,
    "FramedContentTBS",
    tbs(wireFormat, groupContext).encodeUnsafe(),
    authData.signature,
  )

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
    companion object : Encodable<Tbs> {
      override val dataT: DataType<Tbs> =
        throwAnyError {
          struct("FramedContentTBS") {
            it.field("version", ProtocolVersion.T, ProtocolVersion.MLS_1_0)
              .field("wire_format", WireFormat.T)
              .field("content", FramedContent.dataT)
              .select<GroupContext?, _>(SenderType.T, "content", "sender", "sender_type") {
                case(SenderType.Member, SenderType.NewMemberCommit).then(GroupContext.dataT, "context")
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

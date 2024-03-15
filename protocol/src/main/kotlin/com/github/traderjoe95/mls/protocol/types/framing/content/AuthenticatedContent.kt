package com.github.traderjoe95.mls.protocol.types.framing.content

import arrow.core.Either
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.error.VerifySignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class AuthenticatedContent<out C : Content<C>>(
  val wireFormat: WireFormat,
  val framedContent: FramedContent<C>,
  val signature: Signature,
  val confirmationTag: Mac?,
) : Struct4T.Shape<WireFormat, FramedContent<C>, Signature, Mac?> {
  fun verify(
    groupContext: GroupContext,
    signaturePublicKey: SignaturePublicKey,
  ): Either<VerifySignatureError, Unit> =
    framedContent.verifySignature(
      FramedContent.AuthData(signature, confirmationTag),
      wireFormat,
      groupContext,
      signaturePublicKey,
    )

  val sender: Sender
    get() = framedContent.sender
  val senderType: SenderType
    get() = sender.type
  val contentType: ContentType<C>
    get() = framedContent.contentType
  val groupId: GroupId
    get() = framedContent.groupId
  val epoch: ULong
    get() = framedContent.epoch

  fun tbm(groupContext: GroupContext): Tbm = Tbm(framedContent.tbs(wireFormat, groupContext), signature, confirmationTag)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as AuthenticatedContent<*>

    if (wireFormat != other.wireFormat) return false
    if (framedContent != other.framedContent) return false
    if (!signature.bytes.contentEquals(other.signature.bytes)) return false
    if (confirmationTag != null) {
      if (other.confirmationTag == null) return false
      if (!confirmationTag.bytes.contentEquals(other.confirmationTag.bytes)) return false
    } else if (other.confirmationTag != null) {
      return false
    }

    return true
  }

  override fun hashCode(): Int {
    var result = wireFormat.hashCode()
    result = 31 * result + framedContent.hashCode()
    result = 31 * result + signature.bytes.contentHashCode()
    result = 31 * result + (confirmationTag?.bytes?.contentHashCode() ?: 0)
    return result
  }

  companion object : Encodable<AuthenticatedContent<*>> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<AuthenticatedContent<*>> =
      throwAnyError {
        struct("AuthenticatedContent") {
          it.field("wire_format", WireFormat.T)
            .field("content", FramedContent.T)
            .field("signature", Signature.T)
            .select<Mac?, _>(ContentType.T, "content", "content_type") {
              case(ContentType.Commit).then(Mac.T, "confirmation_tag")
                .orElseNothing()
            }
        }.lift { wf, c, sig, ct -> AuthenticatedContent<Content<*>>(wf, c, sig, ct) }
      }
  }

  data class Tbm(
    val contentTbs: FramedContent.Tbs,
    val signature: Signature,
    val confirmationTag: Mac?,
  ) : Struct3T.Shape<FramedContent.Tbs, Signature, Mac?> {
    companion object : Encodable<Tbm> {
      @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
      override val T: DataType<Tbm> =
        throwAnyError {
          struct("AuthenticatedContentTBM") {
            it.field("content_tbs", FramedContent.Tbs.T)
              .field("signature", Signature.T)
              .select<Mac?, _>(ContentType.T, "content_tbs", "content", "content_type") {
                case(ContentType.Commit).then(Mac.T, "confirmation_tag")
                  .orElseNothing()
              }
          }.lift(::Tbm)
        }
    }

    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (javaClass != other?.javaClass) return false

      other as Tbm

      if (contentTbs != other.contentTbs) return false
      if (!signature.bytes.contentEquals(other.signature.bytes)) return false
      if (confirmationTag != null) {
        if (other.confirmationTag == null) return false
        if (!confirmationTag.bytes.contentEquals(other.confirmationTag.bytes)) return false
      } else if (other.confirmationTag != null) {
        return false
      }

      return true
    }

    override fun hashCode(): Int {
      var result = contentTbs.hashCode()
      result = 31 * result + signature.bytes.contentHashCode()
      result = 31 * result + (confirmationTag?.bytes?.contentHashCode() ?: 0)
      return result
    }
  }
}

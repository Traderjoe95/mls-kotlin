package com.github.traderjoe95.mls.protocol.types.framing.content

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.Struct4T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.MacError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class AuthenticatedContent<out C : Content>(
  val wireFormat: WireFormat,
  val content: FramedContent<C>,
  val signature: Signature,
  val confirmationTag: Mac?,
) : Struct4T.Shape<WireFormat, FramedContent<C>, Signature, Mac?> {
  context(GroupState, Raise<EncoderError>, Raise<SignatureError>, Raise<MacError>, Raise<EpochError>)
  fun verify(
    groupContext: GroupContext,
  ) {
    content.verifySignature(FramedContent.AuthData(signature, confirmationTag), wireFormat, groupContext)
  }

  val sender: Sender
    get() = content.sender
  val senderType: SenderType
    get() = sender.type
  val contentType: ContentType
    get() = content.contentType
  val epoch: ULong
    get() = content.epoch

  fun tbm(groupContext: GroupContext): Tbm = Tbm(content.tbs(wireFormat, groupContext), signature, confirmationTag)

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as AuthenticatedContent<*>

    if (wireFormat != other.wireFormat) return false
    if (content != other.content) return false
    if (!signature.value.contentEquals(other.signature.value)) return false
    if (confirmationTag != null) {
      if (other.confirmationTag == null) return false
      if (!confirmationTag.value.contentEquals(other.confirmationTag.value)) return false
    } else if (other.confirmationTag != null) {
      return false
    }

    return true
  }

  override fun hashCode(): Int {
    var result = wireFormat.hashCode()
    result = 31 * result + content.hashCode()
    result = 31 * result + signature.value.contentHashCode()
    result = 31 * result + (confirmationTag?.value?.contentHashCode() ?: 0)
    return result
  }

  data class Tbm(
    val contentTbs: FramedContent.Tbs,
    val signature: Signature,
    val confirmationTag: Mac?,
  ) : Struct3T.Shape<FramedContent.Tbs, Signature, Mac?> {
    companion object {
      val T: DataType<Tbm> =
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
      if (!signature.value.contentEquals(other.signature.value)) return false
      if (confirmationTag != null) {
        if (other.confirmationTag == null) return false
        if (!confirmationTag.value.contentEquals(other.confirmationTag.value)) return false
      } else if (other.confirmationTag != null) {
        return false
      }

      return true
    }

    override fun hashCode(): Int {
      var result = contentTbs.hashCode()
      result = 31 * result + signature.value.contentHashCode()
      result = 31 * result + (confirmationTag?.value?.contentHashCode() ?: 0)
      return result
    }
  }
}

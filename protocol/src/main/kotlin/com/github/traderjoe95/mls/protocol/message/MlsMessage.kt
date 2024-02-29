package com.github.traderjoe95.mls.protocol.message

import arrow.core.raise.Raise
import arrow.core.raise.ensure
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.MessageRecipientError
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion.MLS_1_0
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class MlsMessage<out M : Message>
  @PublishedApi
  internal constructor(
    val protocolVersion: ProtocolVersion,
    val wireFormat: WireFormat,
    val message: M,
  ) : Struct3T.Shape<ProtocolVersion, WireFormat, M> {
    companion object : Encodable<MlsMessage<*>> {
      internal fun <C : Content<C>> public(message: PublicMessage<C>): MlsMessage<PublicMessage<C>> =
        MlsMessage(MLS_1_0, WireFormat.MlsPublicMessage, message)

      internal fun <C : Content<C>> private(message: PrivateMessage<C>): MlsMessage<PrivateMessage<C>> =
        MlsMessage(MLS_1_0, WireFormat.MlsPrivateMessage, message)

      fun welcome(
        cipherSuite: CipherSuite,
        encryptedGroupSecrets: List<EncryptedGroupSecrets>,
        encryptedGroupInfo: Ciphertext,
      ): MlsMessage<Welcome> = welcome(Welcome(cipherSuite, encryptedGroupSecrets, encryptedGroupInfo))

      @JvmStatic
      fun welcome(message: Welcome): MlsMessage<Welcome> = MlsMessage(MLS_1_0, WireFormat.MlsWelcome, message)

      @JvmStatic
      fun groupInfo(message: GroupInfo): MlsMessage<GroupInfo> = MlsMessage(MLS_1_0, WireFormat.MlsGroupInfo, message)

      @JvmStatic
      fun keyPackage(message: KeyPackage): MlsMessage<KeyPackage> = MlsMessage(MLS_1_0, WireFormat.MlsKeyPackage, message)

      inline fun <reified M : Message> MlsMessage<Message>.coerceFormat(): MlsMessage<M> =
        MlsMessage(protocolVersion, wireFormat, message as M)

      context(Raise<MessageRecipientError.UnexpectedWireFormat>)
      inline fun <reified M : Message> MlsMessage<Message>.ensureFormat(): MlsMessage<M> =
        if (message is M) {
          MlsMessage(protocolVersion, wireFormat, message)
        } else {
          raise(MessageRecipientError.UnexpectedWireFormat(this.wireFormat, wireFormat))
        }

      context(Raise<MessageRecipientError.UnexpectedWireFormat>)
      inline fun <reified M : GroupMessage<*>> MlsMessage<Message>.ensureFormat(wireFormat: WireFormat): MlsMessage<M> =
        if (message is M && this.wireFormat == wireFormat) {
          MlsMessage(protocolVersion, wireFormat, message)
        } else {
          raise(MessageRecipientError.UnexpectedWireFormat(this.wireFormat, wireFormat))
        }

      context(Raise<MessageRecipientError>)
      inline fun <C : Content<C>, reified M : GroupMessage<C>> MlsMessage<Message>.ensureFormatAndContent(
        wireFormat: WireFormat,
        contentType: ContentType<C>,
      ): MlsMessage<M> =
        if (message is M && this.wireFormat == wireFormat) {
          MlsMessage(protocolVersion, wireFormat, message).also {
            ensure(message.contentType == contentType) {
              MessageRecipientError.UnexpectedContent(
                message.contentType,
                contentType,
              )
            }
          }
        } else {
          raise(MessageRecipientError.UnexpectedWireFormat(this.wireFormat, wireFormat))
        }

      override val dataT: DataType<MlsMessage<*>> =
        throwAnyError {
          struct("MLSMessage") {
            it.field("version", ProtocolVersion.T, MLS_1_0)
              .field("wire_format", WireFormat.T)
              .select<Message, _>(WireFormat.T, "wire_format") {
                case(WireFormat.MlsPublicMessage).then(PublicMessage.dataT, "public_message")
                  .case(WireFormat.MlsPrivateMessage).then(PrivateMessage.dataT, "private_message")
                  .case(WireFormat.MlsWelcome).then(Welcome.dataT, "welcome")
                  .case(WireFormat.MlsGroupInfo).then(GroupInfo.dataT, "group_info")
                  .case(WireFormat.MlsKeyPackage).then(KeyPackage.dataT, "key_package")
              }
          }.lift(::MlsMessage)
        }
    }
  }

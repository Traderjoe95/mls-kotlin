package com.github.traderjoe95.mls.protocol.types.framing

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct3T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.PrivateMessageSenderError
import com.github.traderjoe95.mls.protocol.error.PublicMessageSenderError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.createFramedContent
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion.MLS_1_0
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.framing.message.EncryptedGroupSecrets
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.framing.message.Message
import com.github.traderjoe95.mls.protocol.types.framing.message.PrivateMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.PublicMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome

data class MlsMessage<out M : Message> internal constructor(
  val protocolVersion: ProtocolVersion,
  val wireFormat: WireFormat,
  val message: M,
) : Struct3T.Shape<ProtocolVersion, WireFormat, M> {
  companion object : Encodable<MlsMessage<*>> {
    context(ICipherSuite, KeySchedule, Raise<PublicMessageSenderError>)
    fun <C : Content> public(
      authenticatedContent: AuthenticatedContent<C>,
      groupContext: GroupContext,
    ): MlsMessage<PublicMessage<C>> = public(PublicMessage.create(authenticatedContent, groupContext))

    context(GroupState, Raise<PublicMessageSenderError>)
    fun <C : Content> public(
      framedContent: FramedContent<C>,
      authData: FramedContent.AuthData,
    ): MlsMessage<PublicMessage<C>> =
      public(
        AuthenticatedContent(
          WireFormat.MlsPublicMessage,
          framedContent,
          authData.signature,
          authData.confirmationTag,
        ),
      )

    context(GroupState, Raise<PublicMessageSenderError>)
    fun <C : Content> public(
      authenticatedContent: AuthenticatedContent<C>,
    ): MlsMessage<PublicMessage<C>> = public(PublicMessage.create(authenticatedContent))

    context(GroupState, Raise<PublicMessageSenderError>)
    fun public(
      applicationData: ApplicationData,
      authenticatedData: ByteArray = byteArrayOf(),
    ): MlsMessage<PublicMessage<ApplicationData>> =
      ensureActive {
        createFramedContent(applicationData, authenticatedData).let { framedContent ->
          public(
            PublicMessage.create(
              AuthenticatedContent(
                WireFormat.MlsPublicMessage,
                framedContent,
                framedContent.sign(WireFormat.MlsPublicMessage, groupContext, signingKey),
                null,
              ),
            ),
          )
        }
      }

    fun <C : Content> public(message: PublicMessage<C>): MlsMessage<PublicMessage<C>> =
      MlsMessage(MLS_1_0, WireFormat.MlsPublicMessage, message)

    context(GroupState, Raise<PrivateMessageSenderError>)
    suspend fun private(
      framedContent: FramedContent<*>,
      authData: FramedContent.AuthData,
    ): MlsMessage<PrivateMessage> =
      private(
        PrivateMessage.create(
          AuthenticatedContent(
            WireFormat.MlsPrivateMessage,
            framedContent,
            authData.signature,
            authData.confirmationTag,
          ),
        ),
      )

    context(GroupState, Raise<PrivateMessageSenderError>)
    suspend fun private(
      applicationData: ApplicationData,
      authenticatedData: ByteArray = byteArrayOf(),
    ): MlsMessage<PrivateMessage> =
      ensureActive {
        private(
          createFramedContent(applicationData, authenticatedData).let { framedContent ->
            PrivateMessage.create(
              AuthenticatedContent(
                WireFormat.MlsPrivateMessage,
                framedContent,
                framedContent.sign(WireFormat.MlsPrivateMessage, groupContext, signingKey),
                null,
              ),
            )
          },
        )
      }

    fun private(message: PrivateMessage): MlsMessage<PrivateMessage> = MlsMessage(MLS_1_0, WireFormat.MlsPrivateMessage, message)

    fun welcome(
      cipherSuite: CipherSuite,
      encryptedGroupSecrets: List<EncryptedGroupSecrets>,
      encryptedGroupInfo: Ciphertext,
    ): MlsMessage<Welcome> = welcome(Welcome(cipherSuite, encryptedGroupSecrets, encryptedGroupInfo))

    fun welcome(message: Welcome): MlsMessage<Welcome> = MlsMessage(MLS_1_0, WireFormat.MlsWelcome, message)

    fun groupInfo(message: GroupInfo): MlsMessage<GroupInfo> = MlsMessage(MLS_1_0, WireFormat.MlsGroupInfo, message)

    fun keyPackage(message: KeyPackage): MlsMessage<KeyPackage> = MlsMessage(MLS_1_0, WireFormat.MlsKeyPackage, message)

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

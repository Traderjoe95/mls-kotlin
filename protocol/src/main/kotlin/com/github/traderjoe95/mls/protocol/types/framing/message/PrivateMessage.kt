package com.github.traderjoe95.mls.protocol.types.framing.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.Struct3
import com.github.traderjoe95.mls.codec.Struct4
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.decodeWithPadding
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct6T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.codec.type.uint64
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.MessageSenderError
import com.github.traderjoe95.mls.protocol.error.PrivateMessageRecipientError
import com.github.traderjoe95.mls.protocol.error.PrivateMessageSenderError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.T
import com.github.traderjoe95.mls.protocol.types.crypto.Aad.Companion.asAad
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.ReuseGuard
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.types.framing.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.types.framing.message.padding.deterministic.Padme
import de.traderjoe.ulid.ULID
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

data class PrivateMessage(
  override val groupId: ULID,
  override val epoch: ULong,
  override val contentType: ContentType,
  val authenticatedData: ByteArray,
  val encryptedSenderData: Ciphertext,
  val ciphertext: Ciphertext,
) : GroupMessage<PrivateMessageRecipientError>,
  Struct6T.Shape<ULID, ULong, ContentType, ByteArray, Ciphertext, Ciphertext> {
  constructor(framedContent: FramedContent<*>, encryptedSenderData: Ciphertext, ciphertext: Ciphertext) : this(
    framedContent.groupId,
    framedContent.epoch,
    framedContent.contentType,
    framedContent.authenticatedData,
    encryptedSenderData,
    ciphertext,
  )

  private fun privateContentAad(): Struct4<ULID, ULong, ContentType, ByteArray> = Struct4(groupId, epoch, contentType, authenticatedData)

  private fun senderDataAad(): Struct3<ULID, ULong, ContentType> = Struct3(groupId, epoch, contentType)

  context(GroupState, Raise<PrivateMessageRecipientError>)
  override suspend fun getAuthenticatedContent(): AuthenticatedContent<*> =
    EncoderError.wrap {
      val ciphertextSample = ciphertext.value.sliceArray(0..<minOf(ciphertext.size, hashLen.toInt()))

      val senderDataKey = expandWithLabel(keySchedule(epoch).senderDataSecret, "key", ciphertextSample, keyLen)
      val senderDataNonce =
        expandWithLabel(keySchedule(epoch).senderDataSecret, "nonce", ciphertextSample, nonceLen).asNonce

      val senderData =
        try {
          DecoderError.wrap {
            decryptAead(
              senderDataKey,
              senderDataNonce,
              SENDER_DATA_AAD_T.encode(senderDataAad()).asAad,
              encryptedSenderData,
            ).decodeAs(SENDER_DATA_T)
          }
        } finally {
          senderDataNonce.wipe()
          senderDataKey.wipe()
        }

      val leafIndex = senderData.field1
      val generation = senderData.field2
      val reuseGuard = senderData.field3

      val (nonce, key) = getNonceAndKey(epoch, leafIndex, contentType, generation)
      val guardedNonce = nonce xor reuseGuard

      val plaintextContent =
        try {
          decryptAead(
            key,
            guardedNonce,
            AAD_T.encode(privateContentAad()).asAad,
            ciphertext,
          )
        } finally {
          nonce.wipe()
          guardedNonce.wipe()
          key.wipe()
        }

      val (content, authData) =
        DecoderError.wrap {
          when (contentType) {
            ContentType.Application ->
              plaintextContent.decodeWithPadding(APPLICATION_CONTENT_T)
                .let { (content, signature) ->
                  content to FramedContent.AuthData(signature, null)
                }

            ContentType.Proposal ->
              plaintextContent.decodeWithPadding(PROPOSAL_CONTENT_T).let { (proposal, signature) ->
                proposal to FramedContent.AuthData(signature, null)
              }

            ContentType.Commit ->
              plaintextContent.decodeWithPadding(COMMIT_CONTENT_T)
                .let { (commit, signature, confirmationTag) ->
                  commit to FramedContent.AuthData(signature, confirmationTag)
                }

            else -> error("Bad content type")
          }
        }

      AuthenticatedContent(
        WireFormat.MlsPrivateMessage,
        FramedContent(
          groupId,
          epoch,
          Sender.member(leafIndex),
          authenticatedData,
          contentType,
          content,
        ),
        authData.signature,
        authData.confirmationTag,
      ).apply { verify(groupContext(epoch)) }
    }

  companion object {
    val T: DataType<PrivateMessage> =
      struct("PrivateMessage") {
        it.field("group_id", ULID.T)
          .field("epoch", uint64.asULong)
          .field("content_type", ContentType.T)
          .field("authenticated_data", opaque[V])
          .field("encrypted_sender_data", Ciphertext.T)
          .field("ciphertext", Ciphertext.T)
      }.lift(::PrivateMessage)

    context(GroupState, Raise<PrivateMessageSenderError>)
    suspend fun create(
      authContent: AuthenticatedContent<*>,
      paddingStrategy: PaddingStrategy = Padme,
    ): PrivateMessage =
      EncoderError.wrap {
        if (authContent.senderType != SenderType.Member) {
          raise(
            MessageSenderError.InvalidSenderType(
              authContent.senderType,
              "Private messages can only be sent by members",
            ),
          )
        }

        val leafIndex = authContent.sender.index!!
        val (nonce, key, generation) = getNonceAndKey(leafIndex, authContent.contentType)
        val reuseGuard = ReuseGuard.random()
        val guardedNonce = nonce xor reuseGuard

        val ciphertext =
          try {
            encryptAead(
              key,
              guardedNonce,
              AAD_T.encode(aad(authContent.content)).asAad,
              encodePrivateMessageContent(authContent, paddingStrategy),
            )
          } finally {
            nonce.wipe()
            guardedNonce.wipe()
            key.wipe()
          }

        val senderData =
          SENDER_DATA_T.encode(Struct3(leafIndex, generation, reuseGuard))
        val ciphertextSample = ciphertext.value.sliceArray(0..<minOf(ciphertext.size, hashLen.toInt()))
        val senderDataKey = expandWithLabel(keySchedule.senderDataSecret, "key", ciphertextSample, keyLen)
        val senderDataNonce = expandWithLabel(keySchedule.senderDataSecret, "nonce", ciphertextSample, nonceLen).asNonce

        val encryptedSenderData =
          try {
            encryptAead(
              senderDataKey,
              senderDataNonce,
              SENDER_DATA_AAD_T.encode(senderDataAad(authContent.content)).asAad,
              senderData,
            )
          } finally {
            senderDataNonce.wipe()
            senderDataKey.wipe()
          }

        PrivateMessage(authContent.content, encryptedSenderData, ciphertext)
      }

    context(GroupState, Raise<BaseEncoderError>)
    @Suppress("kotlin:S1481")
    private fun encodePrivateMessageContent(
      authContent: AuthenticatedContent<*>,
      paddingStrategy: PaddingStrategy,
    ): ByteArray {
      val contentAndAuth =
        when (authContent.contentType) {
          ContentType.Application ->
            APPLICATION_CONTENT_T.encode(
              Struct2(authContent.content.content as ApplicationData, authContent.signature),
            )

          ContentType.Proposal ->
            PROPOSAL_CONTENT_T.encode(
              Struct2(authContent.content.content as Proposal, authContent.signature),
            )

          ContentType.Commit -> {
            COMMIT_CONTENT_T.encode(
              Struct3(authContent.content.content as Commit, authContent.signature, authContent.confirmationTag!!),
            )
          }

          else -> error("Bad content type")
        }

      return paddingStrategy.applyPadding(contentAndAuth)
    }

    private val APPLICATION_CONTENT_T =
      struct("PrivateMessageContent") {
        it.field("application_data", ApplicationData.T)
          .field("signature", Signature.T)
      }

    private val PROPOSAL_CONTENT_T =
      struct("PrivateMessageContent") {
        it.field("proposal", Proposal.T)
          .field("signature", Signature.T)
      }

    private val COMMIT_CONTENT_T =
      struct("PrivateMessageContent") {
        it.field("commit", Commit.T)
          .field("signature", Signature.T)
          .field("confirmation_tag", Mac.T)
      }

    private fun aad(framedContent: FramedContent<*>): Struct4<ULID, ULong, ContentType, ByteArray> =
      Struct4(framedContent.groupId, framedContent.epoch, framedContent.contentType, framedContent.authenticatedData)

    private val AAD_T =
      struct("PrivateContentAAD") {
        it.field("group_id", ULID.T)
          .field("epoch", uint64.asULong)
          .field("content_type", ContentType.T)
          .field("authenticated_data", opaque[V])
      }

    private val SENDER_DATA_T =
      struct("SenderData") {
        it.field("leaf_index", uint32.asUInt)
          .field("generation", uint32.asUInt)
          .field("reuse_guard", ReuseGuard.T)
      }

    private fun senderDataAad(framedContent: FramedContent<*>): Struct3<ULID, ULong, ContentType> =
      Struct3(framedContent.groupId, framedContent.epoch, framedContent.contentType)

    private val SENDER_DATA_AAD_T =
      struct("SenderDataAAD") {
        it.field("group_id", ULID.T)
          .field("epoch", uint64.asULong)
          .field("content_type", ContentType.T)
      }
  }
}

package com.github.traderjoe95.mls.protocol.message

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.Encodable
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
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.MessageSenderError
import com.github.traderjoe95.mls.protocol.error.PrivateMessageRecipientError
import com.github.traderjoe95.mls.protocol.error.PrivateMessageSenderError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.message.padding.PaddingStrategy
import com.github.traderjoe95.mls.protocol.message.padding.deterministic.Padme
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.tree.SignaturePublicKeyLookup
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Aad.Companion.asAad
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.ReuseGuard
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.enums.SenderType
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat

data class PrivateMessage<out C : Content<C>>(
  override val groupId: GroupId,
  override val epoch: ULong,
  override val contentType: ContentType<C>,
  val authenticatedData: ByteArray,
  val encryptedSenderData: Ciphertext,
  val ciphertext: Ciphertext,
) : GroupMessage<C>,
  Struct6T.Shape<GroupId, ULong, ContentType<C>, ByteArray, Ciphertext, Ciphertext> {
  override val wireFormat: WireFormat = WireFormat.MlsPrivateMessage

  override val encoded: ByteArray by lazy { encodeUnsafe() }

  constructor(framedContent: FramedContent<C>, encryptedSenderData: Ciphertext, ciphertext: Ciphertext) : this(
    framedContent.groupId,
    framedContent.epoch,
    framedContent.contentType,
    framedContent.authenticatedData,
    encryptedSenderData,
    ciphertext,
  )

  private fun privateContentAad(): Struct4<GroupId, ULong, ContentType<C>, ByteArray> =
    Struct4(groupId, epoch, contentType, authenticatedData)

  private fun senderDataAad(): Struct3<GroupId, ULong, ContentType<C>> = Struct3(groupId, epoch, contentType)

  override suspend fun unprotect(groupState: GroupState.Active): Either<PrivateMessageRecipientError, AuthenticatedContent<C>> =
    unprotect(
      groupState.groupContext,
      groupState.keySchedule.senderDataSecret,
      groupState.secretTree,
      groupState.tree,
    )

  suspend fun unprotect(
    groupContext: GroupContext,
    senderDataSecret: Secret,
    secretTree: SecretTree,
    signaturePublicKeyLookup: SignaturePublicKeyLookup,
  ): Either<PrivateMessageRecipientError, AuthenticatedContent<C>> =
    either {
      with(groupContext.cipherSuite) {
        val (senderDataNonce, senderDataKey) = getSenderDataNonceAndKey(this, senderDataSecret, ciphertext)

        val senderData =
          try {
            DecoderError.wrap {
              decryptAead(
                senderDataKey,
                senderDataNonce,
                SENDER_DATA_AAD_T.encodeUnsafe(senderDataAad()).asAad,
                encryptedSenderData,
              ).bind().decodeAs(SENDER_DATA_T)
            }
          } finally {
            senderDataNonce.wipe()
            senderDataKey.wipe()
          }

        val leafIndex = senderData.field1
        val generation = senderData.field2
        val reuseGuard = senderData.field3

        val (nonce, key) = secretTree.getNonceAndKey(leafIndex, contentType, generation)
        val guardedNonce = nonce xor reuseGuard

        val plaintextContent =
          try {
            decryptAead(
              key,
              guardedNonce,
              AAD_T.encodeUnsafe(privateContentAad()).asAad,
              ciphertext,
            ).bind()
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

        @Suppress("UNCHECKED_CAST")
        AuthenticatedContent(
          WireFormat.MlsPrivateMessage,
          FramedContent(
            groupId,
            epoch,
            Sender.member(leafIndex),
            authenticatedData,
            contentType,
            content as C,
          ),
          authData.signature,
          authData.confirmationTag,
        ).apply { verify(groupContext, signaturePublicKeyLookup.getSignaturePublicKey(groupContext, this.framedContent)) }
      }
    }

  companion object : Encodable<PrivateMessage<*>> {
    override val dataT: DataType<PrivateMessage<*>> =
      struct("PrivateMessage") {
        it.field("group_id", GroupId.dataT)
          .field("epoch", uint64.asULong)
          .field("content_type", ContentType.T)
          .field("authenticated_data", opaque[V])
          .field("encrypted_sender_data", Ciphertext.dataT)
          .field("ciphertext", Ciphertext.dataT)
      }.lift { g, e, ct, aad, esd, ciph -> PrivateMessage(g, e, ct as ContentType<Content<*>>, aad, esd, ciph) }

    context(Raise<PrivateMessageSenderError>)
    suspend fun <C : Content<C>> create(
      cipherSuite: ICipherSuite,
      authContent: AuthenticatedContent<C>,
      secretTree: SecretTree,
      senderDataSecret: Secret,
      paddingStrategy: PaddingStrategy = Padme,
    ): PrivateMessage<C> {
      if (authContent.senderType != SenderType.Member) {
        raise(
          MessageSenderError.InvalidSenderType(
            authContent.senderType,
            "Private messages can only be sent by members",
          ),
        )
      }

      val leafIndex = authContent.sender.index!!
      val (nonce, key, generation) =
        secretTree.getNonceAndKey(leafIndex, authContent.contentType)
      val reuseGuard = ReuseGuard.random()
      val guardedNonce = nonce xor reuseGuard

      val ciphertext =
        try {
          cipherSuite.encryptAead(
            key,
            guardedNonce,
            AAD_T.encodeUnsafe(aad(authContent.framedContent)).asAad,
            encodePrivateMessageContent(authContent, paddingStrategy),
          )
        } finally {
          nonce.wipe()
          guardedNonce.wipe()
          key.wipe()
        }

      val senderData =
        SENDER_DATA_T.encodeUnsafe(Struct3(leafIndex, generation, reuseGuard))
      val (senderDataNonce, senderDataKey) = getSenderDataNonceAndKey(cipherSuite, senderDataSecret, ciphertext)
      val encryptedSenderData =
        try {
          cipherSuite.encryptAead(
            senderDataKey,
            senderDataNonce,
            SENDER_DATA_AAD_T.encodeUnsafe(senderDataAad(authContent.framedContent)).asAad,
            senderData,
          )
        } finally {
          senderDataNonce.wipe()
          senderDataKey.wipe()
        }

      return PrivateMessage(authContent.framedContent, encryptedSenderData, ciphertext)
    }

    fun getSenderDataNonceAndKey(
      cipherSuite: ICipherSuite,
      senderDataSecret: Secret,
      ciphertext: Ciphertext,
    ): Pair<Nonce, Secret> =
      with(cipherSuite) {
        ciphertext.bytes.sliceArray(0..<minOf(ciphertext.size, hashLen.toInt())).let { ciphertextSample ->
          expandWithLabel(
            senderDataSecret,
            "nonce",
            ciphertextSample,
            nonceLen,
          ).asNonce to
            expandWithLabel(
              senderDataSecret,
              "key",
              ciphertextSample,
              keyLen,
            )
        }
      }

    @Suppress("kotlin:S1481")
    private fun encodePrivateMessageContent(
      authContent: AuthenticatedContent<*>,
      paddingStrategy: PaddingStrategy,
    ): ByteArray {
      val contentAndAuth =
        when (authContent.contentType) {
          ContentType.Application ->
            APPLICATION_CONTENT_T.encodeUnsafe(
              Struct2(authContent.framedContent.content as ApplicationData, authContent.signature),
            )

          ContentType.Proposal ->
            PROPOSAL_CONTENT_T.encodeUnsafe(
              Struct2(authContent.framedContent.content as Proposal, authContent.signature),
            )

          ContentType.Commit -> {
            COMMIT_CONTENT_T.encodeUnsafe(
              Struct3(authContent.framedContent.content as Commit, authContent.signature, authContent.confirmationTag!!),
            )
          }

          else -> error("Bad content type")
        }

      return paddingStrategy.applyPadding(contentAndAuth)
    }

    private val APPLICATION_CONTENT_T =
      struct("PrivateMessageContent") {
        it.field("application_data", ApplicationData.dataT)
          .field("signature", Signature.dataT)
      }

    private val PROPOSAL_CONTENT_T =
      struct("PrivateMessageContent") {
        it.field("proposal", Proposal.dataT)
          .field("signature", Signature.dataT)
      }

    private val COMMIT_CONTENT_T =
      struct("PrivateMessageContent") {
        it.field("commit", Commit.dataT)
          .field("signature", Signature.dataT)
          .field("confirmation_tag", Mac.dataT)
      }

    private fun <C : Content<C>> aad(framedContent: FramedContent<C>): Struct4<GroupId, ULong, ContentType<C>, ByteArray> =
      Struct4(framedContent.groupId, framedContent.epoch, framedContent.contentType, framedContent.authenticatedData)

    private val AAD_T =
      struct("PrivateContentAAD") {
        it.field("group_id", GroupId.dataT)
          .field("epoch", uint64.asULong)
          .field("content_type", ContentType.T)
          .field("authenticated_data", opaque[V])
      }

    private val SENDER_DATA_T =
      struct("SenderData") {
        it.field("leaf_index", LeafIndex.dataT)
          .field("generation", uint32.asUInt)
          .field("reuse_guard", ReuseGuard.dataT)
      }

    private fun <C : Content<C>> senderDataAad(framedContent: FramedContent<C>): Struct3<GroupId, ULong, ContentType<C>> =
      Struct3(framedContent.groupId, framedContent.epoch, framedContent.contentType)

    private val SENDER_DATA_AAD_T =
      struct("SenderDataAAD") {
        it.field("group_id", GroupId.dataT)
          .field("epoch", uint64.asULong)
          .field("content_type", ContentType.T)
      }
  }
}

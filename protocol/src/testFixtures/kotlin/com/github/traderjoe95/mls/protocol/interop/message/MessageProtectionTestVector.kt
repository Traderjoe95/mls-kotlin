package com.github.traderjoe95.mls.protocol.message

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.interop.util.getApplicationData
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getGroupId
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.getSignaturePrivateKey
import com.github.traderjoe95.mls.protocol.interop.util.getSignaturePublicKey
import com.github.traderjoe95.mls.protocol.interop.util.getULong
import com.github.traderjoe95.mls.protocol.interop.util.nextCommit
import com.github.traderjoe95.mls.protocol.interop.util.nextProposal
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.coerceFormat
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Mac.Companion.asMac
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextULong

class MessageProtectionTestVector(
  val cipherSuite: CipherSuite,
  val groupId: GroupId,
  val epoch: ULong,
  val treeHash: ByteArray,
  val confirmedTranscriptHash: ByteArray,
  val signaturePriv: SignaturePrivateKey,
  val signaturePub: SignaturePublicKey,
  val encryptionSecret: Secret,
  val senderDataSecret: Secret,
  val membershipKey: Secret,
  val proposal: Proposal,
  val proposalPub: MlsMessage<PublicMessage<Proposal>>,
  val proposalPriv: MlsMessage<PrivateMessage<Proposal>>,
  val commit: Commit,
  val commitPub: MlsMessage<PublicMessage<Commit>>,
  val commitPriv: MlsMessage<PrivateMessage<Commit>>,
  val application: ApplicationData,
  val applicationPriv: MlsMessage<ApplicationMessage>,
) {
  val groupContext: GroupContext
    get() = GroupContext(ProtocolVersion.MLS_1_0, cipherSuite, groupId, epoch, treeHash, confirmedTranscriptHash)

  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getGroupId("group_id"),
    json.getULong("epoch"),
    json.getHexBinary("tree_hash"),
    json.getHexBinary("confirmed_transcript_hash"),
    json.getSignaturePrivateKey("signature_priv"),
    json.getSignaturePublicKey("signature_pub"),
    json.getSecret("encryption_secret"),
    json.getSecret("sender_data_secret"),
    json.getSecret("membership_key"),
    Proposal.decodeUnsafe(json.getHexBinary("proposal")),
    MlsMessage.decodeUnsafe(json.getHexBinary("proposal_pub")).coerceFormat<PublicMessage<Proposal>>(),
    MlsMessage.decodeUnsafe(json.getHexBinary("proposal_priv")).coerceFormat<PrivateMessage<Proposal>>(),
    Commit.decodeUnsafe(json.getHexBinary("commit")),
    MlsMessage.decodeUnsafe(json.getHexBinary("commit_pub")).coerceFormat<PublicMessage<Commit>>(),
    MlsMessage.decodeUnsafe(json.getHexBinary("commit_priv")).coerceFormat<PrivateMessage<Commit>>(),
    json.getApplicationData("application"),
    MlsMessage.decodeUnsafe(json.getHexBinary("application_priv")).coerceFormat<ApplicationMessage>(),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/message-protection.json",
    ): List<MessageProtectionTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { MessageProtectionTestVector(it as JsonObject) }

    suspend fun generate(cipherSuite: CipherSuite): MessageProtectionTestVector =
      unsafe {
        val (signaturePriv, signaturePub) = cipherSuite.generateSignatureKeyPair()
        val encryptionSecret = cipherSuite.generateSecret(cipherSuite.hashLen)
        val senderDataSecret = cipherSuite.generateSecret(cipherSuite.hashLen)
        val membershipKey = cipherSuite.generateSecret(cipherSuite.hashLen)
        val leafIndex = LeafIndex(1U)

        val groupId = GroupId.new()
        val epoch = Random.nextULong()
        val treeHash = cipherSuite.hash(Random.nextBytes(32))
        val confirmedTranscriptHash = cipherSuite.hash(Random.nextBytes(32))

        val groupContext =
          GroupContext(
            ProtocolVersion.MLS_1_0,
            cipherSuite,
            groupId,
            epoch,
            treeHash,
            confirmedTranscriptHash,
            listOf(),
          )

        val messages = {
          GroupMessageFactory(
            PublicRatchetTree.blankWithLeaves(2U),
            membershipKey,
            senderDataSecret,
            SecretTree.create(cipherSuite, encryptionSecret.copy(), 2U),
            groupContext,
            leafIndex,
            signaturePriv,
          )
        }

        val proposal = Random.nextProposal(cipherSuite, groupContext.groupId)
        val commit = Random.nextCommit(cipherSuite, groupContext.groupId)
        val application = ApplicationData(Random.nextBytes(Random.nextInt(1..1024)))

        val proposalPub = messages().protect(proposal, UsePublicMessage)
        val proposalPriv = messages().protect(proposal, UsePrivateMessage())

        val commitAuthPub = messages().createAuthenticatedContent(commit, UsePublicMessage, byteArrayOf())
        val commitAuthPriv = messages().createAuthenticatedContent(commit, UsePrivateMessage(), byteArrayOf())
        val confirmationTag = Random.nextBytes(cipherSuite.hashLen.toInt()).asMac

        val commitPub = messages().protectCommit(commitAuthPub, confirmationTag, UsePublicMessage)
        val commitPriv = messages().protectCommit(commitAuthPriv, confirmationTag, UsePrivateMessage())

        val applicationPriv = messages().applicationMessage(application).bind()

        return MessageProtectionTestVector(
          cipherSuite,
          groupId,
          epoch,
          treeHash,
          confirmedTranscriptHash,
          signaturePriv,
          signaturePub,
          encryptionSecret,
          senderDataSecret,
          membershipKey,
          proposal,
          proposalPub.coerceFormat(),
          proposalPriv.coerceFormat(),
          commit,
          commitPub.coerceFormat(),
          commitPriv.coerceFormat(),
          application,
          applicationPriv,
        )
      }
  }
}

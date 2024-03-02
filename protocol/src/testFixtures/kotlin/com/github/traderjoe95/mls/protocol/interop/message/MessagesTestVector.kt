package com.github.traderjoe95.mls.protocol.interop.message

import arrow.core.None
import arrow.core.some
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.interop.tree.TreeStructure
import com.github.traderjoe95.mls.protocol.interop.util.choice
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.nextCommit
import com.github.traderjoe95.mls.protocol.interop.util.nextExternalInit
import com.github.traderjoe95.mls.protocol.interop.util.nextGroupContextExtensions
import com.github.traderjoe95.mls.protocol.interop.util.nextKeyPackage
import com.github.traderjoe95.mls.protocol.interop.util.nextPreSharedKey
import com.github.traderjoe95.mls.protocol.interop.util.nextReInit
import com.github.traderjoe95.mls.protocol.interop.util.nextUpdate
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.GroupInfo.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.GroupSecrets
import com.github.traderjoe95.mls.protocol.message.GroupSecrets.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.PrivateMessage
import com.github.traderjoe95.mls.protocol.message.PrivateMessage.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.PublicMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskUsage
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.tree.treeHash
import com.github.traderjoe95.mls.protocol.types.ExternalPub
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.RatchetTree
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Mac.Companion.asMac
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce.Companion.asNonce
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextULong

data class MessagesTestVector(
  // MLS Message (non-group)
  val mlsWelcome: ByteArray,
  val mlsGroupInfo: ByteArray,
  val mlsKeyPackage: ByteArray,
  // Misc
  val ratchetTree: ByteArray,
  val groupSecrets: ByteArray,
  // Proposals
  val addProposal: ByteArray,
  val updateProposal: ByteArray,
  val removeProposal: ByteArray,
  val preSharedKeyProposal: ByteArray,
  val reInitProposal: ByteArray,
  val externalInitProposal: ByteArray,
  val groupContextExtensionsProposal: ByteArray,
  // Commit
  val commit: ByteArray,
  // MLS Group Messages
  val publicMessageApplication: ByteArray,
  val publicMessageProposal: ByteArray,
  val publicMessageCommit: ByteArray,
  val privateMessage: ByteArray,
) {
  constructor(json: JsonObject) : this(
    json.getHexBinary("mls_welcome"),
    json.getHexBinary("mls_group_info"),
    json.getHexBinary("mls_key_package"),
    json.getHexBinary("ratchet_tree"),
    json.getHexBinary("group_secrets"),
    json.getHexBinary("add_proposal"),
    json.getHexBinary("update_proposal"),
    json.getHexBinary("remove_proposal"),
    json.getHexBinary("pre_shared_key_proposal"),
    json.getHexBinary("re_init_proposal"),
    json.getHexBinary("external_init_proposal"),
    json.getHexBinary("group_context_extensions_proposal"),
    json.getHexBinary("commit"),
    json.getHexBinary("public_message_application"),
    json.getHexBinary("public_message_proposal"),
    json.getHexBinary("public_message_commit"),
    json.getHexBinary("private_message"),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/messages.json",
    ): List<MessagesTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { MessagesTestVector(it as JsonObject) }

    suspend fun generate(): MessagesTestVector =
      unsafe {
        val cipherSuite = CipherSuite.X25519_CHACHA20_SHA256_ED25519
        val groupId = GroupId.new()
        val epoch = Random.nextULong()

        val tree =
          Random.choice(
            listOf(
              TreeStructure.FullTree(2U),
              TreeStructure.FullTree(3U),
              TreeStructure.FullTree(4U),
              TreeStructure.FullTree(5U),
            ),
          ).generateTree(cipherSuite, groupId)

        val leafIndex = LeafIndex(Random.choice((0U..<tree.private.uSize).toList()))
        val signatureKey = tree.signaturePrivateKeys[leafIndex.value.toInt()]!!

        val groupContext =
          GroupContext(
            ProtocolVersion.MLS_1_0,
            cipherSuite,
            groupId,
            epoch,
            tree.public.treeHash(cipherSuite),
            Random.nextBytes(cipherSuite.hashLen.toInt()),
          )

        val groupInfo =
          GroupInfo.create(
            groupContext,
            Mac(Random.nextBytes(cipherSuite.hashLen.toInt())),
            listOfNotNull(
              if (Random.nextDouble() < 0.5) RatchetTree(tree.public) else null,
              if (Random.nextDouble() < 0.5) {
                ExternalPub(
                  cipherSuite.deriveKeyPair(cipherSuite.generateSecret(cipherSuite.hashLen)).public,
                )
              } else {
                null
              },
            ),
            leafIndex,
            signatureKey,
          ).bind()

        val groupSecrets =
          GroupSecrets(
            cipherSuite.generateSecret(cipherSuite.hashLen),
            if (Random.nextDouble() < 0.5) None else cipherSuite.generateSecret(cipherSuite.hashLen).some(),
            List(Random.nextInt(0..3)) {
              if (Random.nextDouble() < 0.5) {
                ExternalPskId(Random.nextBytes(32), Random.nextBytes(cipherSuite.hashLen.toInt()).asNonce)
              } else {
                ResumptionPskId(
                  Random.choice(ResumptionPskUsage.entries.filter(ResumptionPskUsage::isValid)),
                  GroupId.new(),
                  Random.nextULong(),
                  Random.nextBytes(cipherSuite.hashLen.toInt()).asNonce,
                )
              }
            },
          )

        val joinerExtracted =
          cipherSuite.extract(
            groupSecrets.joinerSecret,
            cipherSuite.generateSecret(cipherSuite.hashLen),
          )
        val welcomeSecret = cipherSuite.deriveSecret(joinerExtracted, "welcome")
        val welcomeNonce =
          cipherSuite.expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), cipherSuite.nonceLen).asNonce
        val welcomeKey = cipherSuite.expandWithLabel(welcomeSecret, "key", byteArrayOf(), cipherSuite.keyLen)

        val encryptedGroupInfo = cipherSuite.encryptAead(welcomeKey, welcomeNonce, Aad.empty, groupInfo.encodeUnsafe())

        val keyPackage = Random.nextKeyPackage(cipherSuite)
        val encryptedGroupSecrets = groupSecrets.encrypt(cipherSuite, keyPackage.public, encryptedGroupInfo).bind()

        val welcome =
          Welcome(
            cipherSuite,
            listOf(encryptedGroupSecrets),
            encryptedGroupInfo,
          )

        val add = Add(keyPackage.public)
        val update = Random.nextUpdate(cipherSuite, groupId)
        val remove = Remove(LeafIndex(Random.choice((0U..tree.private.uSize).toList())))
        val preSharedKey = Random.nextPreSharedKey(cipherSuite)
        val reInit = Random.nextReInit()
        val externalInit = Random.nextExternalInit(cipherSuite)
        val groupContextExtensions = Random.nextGroupContextExtensions(cipherSuite)

        val commit = Random.nextCommit(cipherSuite, groupId)

        val applicationData = Random.nextBytes(64)
        val applicationContent = FramedContent.createMember(ApplicationData(applicationData), groupContext, leafIndex)
        val applicationPublicMessage =
          MlsMessage(
            ProtocolVersion.MLS_1_0,
            WireFormat.MlsPublicMessage,
            PublicMessage(
              applicationContent,
              applicationContent.sign(WireFormat.MlsPublicMessage, groupContext, signatureKey).bind(),
              null,
              Random.nextBytes(cipherSuite.hashLen.toInt()).asMac,
            ),
          )

        val proposalContent =
          FramedContent.createMember(
            Random.choice(listOf(add, update, remove, preSharedKey, remove, externalInit, groupContextExtensions)),
            groupContext,
            leafIndex,
          )
        val proposalPublicMessage =
          MlsMessage(
            ProtocolVersion.MLS_1_0,
            WireFormat.MlsPublicMessage,
            PublicMessage(
              proposalContent,
              proposalContent.sign(WireFormat.MlsPublicMessage, groupContext, signatureKey).bind(),
              null,
              Random.nextBytes(cipherSuite.hashLen.toInt()).asMac,
            ),
          )

        val commitContent = FramedContent.createMember(commit, groupContext, leafIndex)
        val commitPublicMessage =
          MlsMessage(
            ProtocolVersion.MLS_1_0,
            WireFormat.MlsPublicMessage,
            PublicMessage(
              commitContent,
              commitContent.sign(WireFormat.MlsPublicMessage, groupContext, signatureKey).bind(),
              Random.nextBytes(cipherSuite.hashLen.toInt()).asMac,
              Random.nextBytes(cipherSuite.hashLen.toInt()).asMac,
            ),
          )

        val privateMessage =
          unsafe {
            PrivateMessage.create(
              cipherSuite,
              Random.choice(
                listOf(
                  {
                    AuthenticatedContent(
                      WireFormat.MlsPrivateMessage,
                      applicationContent,
                      applicationContent.sign(WireFormat.MlsPrivateMessage, groupContext, signatureKey).bind(),
                      null,
                    )
                  },
                  {
                    AuthenticatedContent(
                      WireFormat.MlsPrivateMessage,
                      proposalContent,
                      proposalContent.sign(WireFormat.MlsPrivateMessage, groupContext, signatureKey).bind(),
                      null,
                    )
                  },
                  {
                    AuthenticatedContent(
                      WireFormat.MlsPrivateMessage,
                      commitContent,
                      commitContent.sign(WireFormat.MlsPrivateMessage, groupContext, signatureKey).bind(),
                      Random.nextBytes(cipherSuite.hashLen.toInt()).asMac,
                    )
                  },
                ),
              )(),
              SecretTree.create(cipherSuite, cipherSuite.generateSecret(cipherSuite.hashLen), tree.public.leaves.uSize),
              cipherSuite.generateSecret(cipherSuite.hashLen),
            )
          }

        return MessagesTestVector(
          MlsMessage.welcome(welcome).encodeUnsafe(),
          MlsMessage.groupInfo(groupInfo).encodeUnsafe(),
          MlsMessage.keyPackage(keyPackage.public).encodeUnsafe(),
          tree.public.encodeUnsafe(),
          groupSecrets.encodeUnsafe(),
          Add.T.encodeUnsafe(add),
          Update.T.encodeUnsafe(update),
          Remove.T.encodeUnsafe(remove),
          PreSharedKey.T.encodeUnsafe(preSharedKey),
          ReInit.T.encodeUnsafe(reInit),
          ExternalInit.T.encodeUnsafe(externalInit),
          GroupContextExtensions.T.encodeUnsafe(groupContextExtensions),
          commit.encodeUnsafe(),
          applicationPublicMessage.encodeUnsafe(),
          proposalPublicMessage.encodeUnsafe(),
          commitPublicMessage.encodeUnsafe(),
          privateMessage.encodeUnsafe(),
        )
      }
  }
}

package com.github.traderjoe95.mls.playground

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.playground.service.AuthenticationService
import com.github.traderjoe95.mls.playground.service.DeliveryService
import com.github.traderjoe95.mls.playground.util.plus
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.BranchJoinError
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.ExternalPskError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.ReInitJoinError
import com.github.traderjoe95.mls.protocol.error.SendToGroupError
import com.github.traderjoe95.mls.protocol.error.UnknownGroup
import com.github.traderjoe95.mls.protocol.group.joinGroup
import com.github.traderjoe95.mls.protocol.group.newGroup
import com.github.traderjoe95.mls.protocol.group.resumption.BranchEvidence
import com.github.traderjoe95.mls.protocol.group.resumption.ReInitEvidence
import com.github.traderjoe95.mls.protocol.types.ApplicationId
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.CredentialType
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.blocking.new
import kotlinx.coroutines.channels.Channel
import java.time.Instant
import kotlin.time.Duration.Companion.hours

class Client(
  val userName: String,
  val applicationId: ULID = ULID.new(),
  private val credential: Credential = BasicCredential(userName.encodeToByteArray()),
) : ApplicationCtx<String>,
  com.github.traderjoe95.mls.protocol.service.AuthenticationService<String> by AuthenticationService,
  com.github.traderjoe95.mls.protocol.service.DeliveryService<String> by DeliveryService {
  private val messages: Channel<Pair<ULID, ByteArray>> = DeliveryService.registerUser(userName)

  private val keyPackages: MutableMap<Int, Triple<KeyPackage, HpkeKeyPair, SigningKey>> = mutableMapOf()
  private lateinit var signingKeyPair: Pair<SigningKey, VerificationKey>

  private val groups: MutableMap<ULID, GroupChat> = mutableMapOf()
  private val suspended: MutableSet<ULID> = mutableSetOf()

  fun generateKeyPackages(amount: UInt) =
    repeat(amount.toInt()) {
      DeliveryService.addKeyPackage(
        userName,
        either { newKeyPackage(Config.cipherSuite) }.getOrElse {
          throw IllegalStateException("Key package creation failed")
        }.first,
      )
    }

  suspend fun createGroup(): Either<GroupCreationError, GroupChat> =
    either {
      GroupChat(
        newGroup(
          Config.cipherSuite,
          RequiredCapabilities(credentialTypes = listOf(CredentialType.Basic)),
        ),
        this@Client,
      ).register()
    }

  suspend fun processNextMessage(): GroupChat? =
    messages.tryReceive().getOrNull()?.let { (messageId, encoded) ->
      println("[$userName] Message received: $messageId")
      processMessage(throwAnyError { encoded.decodeAs(MlsMessage.T) })
    }

  suspend fun drainNewMessages() {
    do {
      val result = processNextMessage()
    } while (result != null)
  }

  private suspend fun processMessage(message: MlsMessage<*>): GroupChat =
    when (val body = message.message) {
      is GroupMessage<*> ->
        when (val group = groups[body.groupId]) {
          null -> error("[$userName] Unknown group ${body.groupId}")
          else ->
            if (body.groupId in suspended && body.epoch >= group.currentEpoch) {
              println(
                "[$userName] Group ${body.groupId} is suspended since epoch ${group.currentEpoch}, " +
                  "dropping message for epoch ${body.epoch}",
              )
              group
            } else {
              group.processMessage(body)
            }
        }

      is Welcome ->
        either {
          println("[$userName] Welcome: Joining Group")
          GroupChat(joinGroup(body), this@Client).register()
        }.getOrElse { error("[$userName] Failed to join group: $it") }

      else -> error("Unexpected message")
    }

  internal fun GroupChat.register(): GroupChat =
    also { groupChat ->
      groups[groupChat.groupId] = groupChat
    }

  override fun getKeyPackage(ref: KeyPackage.Ref): Triple<KeyPackage, HpkeKeyPair, SigningKey>? = keyPackages[ref.hashCode]

  context(Raise<EncoderError>)
  override fun newKeyPackage(cipherSuite: CipherSuite): Triple<KeyPackage, HpkeKeyPair, SigningKey> {
    require(cipherSuite == Config.cipherSuite) { "Cipher Suite is invalid: $cipherSuite" }

    val encryptionKeyPair = cipherSuite.generateHpkeKeyPair()

    if (!::signingKeyPair.isInitialized) {
      signingKeyPair = EncoderError.wrap { cipherSuite.generateSignatureKeyPair() }
    }

    val (signingKey, verificationKey) = signingKeyPair

    val keyPackage =
      EncoderError.wrap {
        with(cipherSuite) {
          KeyPackage.create(
            encryptionKeyPair.public,
            LeafNode.keyPackage(
              encryptionKeyPair.public,
              verificationKey,
              credential,
              Capabilities.create(
                credentials = listOf(credential.credentialType),
              ),
              Lifetime(
                Instant.now(),
                Instant.now() + 24.hours,
              ),
              extensions =
                listOf(
                  ApplicationId(applicationId),
                ),
              signingKey = signingKey,
            ),
            extensions = listOf(),
            signingKey = signingKey,
          )
        }
      }

    return Triple(keyPackage, encryptionKeyPair, signingKey).also {
      keyPackages[cipherSuite.makeKeyPackageRef(keyPackage).hashCode] = it
    }
  }

  override suspend fun sendMessageToGroup(
    message: MlsMessage<*>,
    toGroup: ULID,
  ): Either<SendToGroupError, ULID> = DeliveryService.sendMessageToGroup(message, toGroup, userName)

  context(Raise<PskError>)
  override suspend fun getExternalPsk(id: ByteArray): Secret = raise(ExternalPskError.UnknownExternalPsk(id))

  context(Raise<PskError>)
  override suspend fun getResumptionPsk(
    groupId: ULID,
    epoch: ULong,
  ): Secret = groups[groupId]?.keySchedule(epoch)?.resumptionPsk ?: raise(UnknownGroup(groupId))

  override fun groupIdExists(id: ULID): Boolean = id in groups

  override fun suspendGroup(groupId: ULID) {
    if (groupId in groups) {
      DeliveryService.unregisterGroup(groupId, userName)
      suspended.add(groupId)
    }
  }

  context(Raise<ReInitJoinError>)
  override fun getReInitEvidence(groupId: ULID): ReInitEvidence =
    groups[groupId]?.run {
      ReInitEvidence(
        currentEpoch,
        lastCommitProposals,
        tree.leaves.filterNotNull().map { it.node.credential },
      )
    } ?: raise(UnknownGroup(groupId))

  context(Raise<BranchJoinError>)
  override fun getBranchEvidence(groupId: ULID): BranchEvidence =
    groups[groupId]?.run {
      BranchEvidence(
        settings.protocolVersion,
        settings.cipherSuite,
        tree.leaves.filterNotNull().map { it.node.credential },
      )
    } ?: raise(UnknownGroup(groupId))
}

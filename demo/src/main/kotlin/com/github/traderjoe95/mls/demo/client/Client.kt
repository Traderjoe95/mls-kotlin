package com.github.traderjoe95.mls.demo.client

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.demo.Config
import com.github.traderjoe95.mls.demo.getOrThrow
import com.github.traderjoe95.mls.demo.service.AuthenticationService
import com.github.traderjoe95.mls.demo.service.DeliveryService
import com.github.traderjoe95.mls.demo.util.contains
import com.github.traderjoe95.mls.demo.util.get
import com.github.traderjoe95.mls.demo.util.getOrElse
import com.github.traderjoe95.mls.demo.util.plus
import com.github.traderjoe95.mls.demo.util.set
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.EpochError
import com.github.traderjoe95.mls.protocol.error.ExternalJoinError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.UnknownGroup
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.joinGroup
import com.github.traderjoe95.mls.protocol.group.joinGroupExternal
import com.github.traderjoe95.mls.protocol.group.newGroup
import com.github.traderjoe95.mls.protocol.message.GroupMessage
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskUsage
import com.github.traderjoe95.mls.protocol.types.ApplicationId
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.CredentialType
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.RequiredCapabilities
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import com.github.traderjoe95.mls.protocol.util.hex
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.blocking.new
import kotlinx.coroutines.channels.Channel
import java.time.Instant
import kotlin.time.Duration.Companion.hours

class Client(
  val userName: String,
  val applicationId: ULID = ULID.new(),
  private val credential: Credential = BasicCredential(userName.encodeToByteArray()),
) : PskLookup,
  com.github.traderjoe95.mls.protocol.service.AuthenticationService<String> by AuthenticationService,
  com.github.traderjoe95.mls.protocol.service.DeliveryService<String> by DeliveryService {
  private val messages: Channel<Pair<ULID, ByteArray>> = DeliveryService.registerUser(userName)

  private val keyPackages: MutableMap<Int, KeyPackage.Private> = mutableMapOf()
  private val signatureKeyPairs: MutableMap<CipherSuite, SignatureKeyPair> = mutableMapOf()

  private val groups: MutableMap<Int, GroupChat> = mutableMapOf()
  private val suspended: MutableSet<Int> = mutableSetOf()

  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()

  fun generateKeyPackages(
    amount: UInt,
    cipherSuite: CipherSuite = Config.cipherSuite,
  ) = repeat(amount.toInt()) {
    DeliveryService.addKeyPackage(
      userName,
      newKeyPackage(cipherSuite).public,
    )
  }

  fun createGroup(public: Boolean = false): Either<GroupCreationError, GroupChat> =
    either {
      GroupChat(
        newGroup(
          newKeyPackage(Config.cipherSuite),
          RequiredCapabilities(credentialTypes = listOf(CredentialType.Basic)),
        ),
        this@Client,
      ).apply {
        if (public) makePublic().getOrThrow()
      }.register()
    }

  suspend fun joinPublicGroup(groupId: GroupId): Either<ExternalJoinError, GroupChat> =
    either {
      val groupInfo = DeliveryService.getPublicGroupInfo(groupId).getOrThrow()
      val (group, commit) = groupInfo.joinGroupExternal(newKeyPackage(groupInfo.groupContext.cipherSuite))

      DeliveryService.sendMessageToGroup(commit, groupId)

      GroupChat(
        group,
        this@Client,
      ).register()
    }

  suspend fun processNextMessage(): GroupChat? =
    messages.tryReceive().getOrNull()?.let { (messageId, encoded) ->
      println("[$userName] Message received: $messageId")
      processMessage(throwAnyError { encoded.decodeAs(MlsMessage.dataT) })
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
            if (body.groupId in suspended && body.epoch >= group.state.epoch) {
              println(
                "[$userName] Group ${body.groupId} is suspended since epoch ${group.state.epoch}, " +
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

          val keyPackage = body.secrets.firstNotNullOf { getKeyPackage(it.newMember) }

          GroupChat(
            body.joinGroup(keyPackage, psks = this@Client, resumptionGroup = body.resolveResumption(keyPackage)),
            this@Client,
          ).register()
        }.getOrElse { error("[$userName] Failed to join group: $it") }

      else -> error("Unexpected message")
    }

  context(Raise<WelcomeJoinError>)
  private fun Welcome.resolveResumption(keyPackage: KeyPackage.Private): GroupState? =
    decryptGroupSecrets(keyPackage).preSharedKeyIds
      .filterIsInstance<ResumptionPskId>()
      .firstOrNull { it.usage == ResumptionPskUsage.ReInit || it.usage == ResumptionPskUsage.Branch }
      ?.let { groups[it.pskGroupId] }
      ?.state

  internal fun GroupChat.register(): GroupChat =
    also { groupChat ->
      groups[groupChat.state.groupId] = groupChat
    }

  fun groupIdExists(id: GroupId): Boolean = id in groups

  fun getKeyPackage(ref: KeyPackage.Ref): KeyPackage.Private? = keyPackages[ref.hashCode]

  fun newKeyPackage(cipherSuite: CipherSuite): KeyPackage.Private {
    val initKeyPair = cipherSuite.generateHpkeKeyPair()
    val encryptionKeyPair = cipherSuite.generateHpkeKeyPair()
    val signingKeyPair = signatureKeyPairs.computeIfAbsent(cipherSuite, CipherSuite::generateSignatureKeyPair)

    val (signingKey, verificationKey) = signingKeyPair

    val keyPackage =
      KeyPackage.create(
        cipherSuite,
        initKeyPair.public,
        LeafNode.keyPackage(
          cipherSuite,
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
              ApplicationId(applicationId.toBytes()),
            ),
          signaturePrivateKey = signingKey,
        ),
        extensions = listOf(),
        signaturePrivateKey = signingKey,
      )

    return KeyPackage.Private(keyPackage, initKeyPair.private, encryptionKeyPair.private, signingKey).also {
      keyPackages[cipherSuite.makeKeyPackageRef(keyPackage).hashCode] = it
    }
  }

  context(Raise<PskError>)
  override suspend fun getPreSharedKey(id: PreSharedKeyId): Secret =
    when (id) {
      is ResumptionPskId ->
        groups.getOrElse(id.pskGroupId) { raise(UnknownGroup(id.pskGroupId)) }
          .state
          .run {
            when {
              id.pskEpoch == epoch -> keySchedule.resumptionPsk
              id.pskEpoch < epoch -> raise(EpochError.EpochNotAvailable(id.pskGroupId, id.pskEpoch))
              else -> raise(EpochError.FutureEpoch(id.pskGroupId, id.pskEpoch, epoch))
            }
          }

      is ExternalPskId -> externalPsks[id.pskId.hex] ?: raise(PskError.PskNotFound(id))
    }
}

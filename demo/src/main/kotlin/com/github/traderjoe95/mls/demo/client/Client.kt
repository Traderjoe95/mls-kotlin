package com.github.traderjoe95.mls.demo.client

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.demo.Config
import com.github.traderjoe95.mls.demo.getOrThrow
import com.github.traderjoe95.mls.demo.service.AuthenticationService
import com.github.traderjoe95.mls.demo.service.DeliveryService
import com.github.traderjoe95.mls.protocol.client.ActiveGroupClient
import com.github.traderjoe95.mls.protocol.client.GroupClient
import com.github.traderjoe95.mls.protocol.client.MlsClient
import com.github.traderjoe95.mls.protocol.client.ProcessHandshakeResult
import com.github.traderjoe95.mls.protocol.client.ProcessMessageResult
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.CreateSignatureError
import com.github.traderjoe95.mls.protocol.error.ExternalJoinError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.ApplicationId
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.util.hex
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.blocking.new
import kotlinx.coroutines.channels.Channel

class Client(
  val userName: String,
  val applicationId: ULID = ULID.new(),
  private val credential: Credential = BasicCredential(userName.encodeToByteArray()),
) : com.github.traderjoe95.mls.protocol.service.AuthenticationService<String> by AuthenticationService,
  com.github.traderjoe95.mls.protocol.service.DeliveryService<String> by DeliveryService {
  private val messages: Channel<Pair<ULID, ByteArray>> = DeliveryService.registerUser(userName)

  private val keyPackages: MutableMap<String, KeyPackage.Private> = mutableMapOf()
  private val signatureKeyPairs: MutableMap<CipherSuite, SignatureKeyPair> = mutableMapOf()

  private val mlsClient: MlsClient<String> = MlsClient(this)

  fun generateKeyPackages(
    amount: UInt,
    cipherSuite: CipherSuite = Config.cipherSuite,
  ) = repeat(amount.toInt()) {
    DeliveryService.addKeyPackage(
      userName,
      either { newKeyPackage(cipherSuite) }.getOrElse { error("Error creating key package: $it") }.public,
    )
  }

  fun createGroup(): Either<GroupCreationError, ActiveGroupClient<String>> =
    // As this function takes ownership of the signature private key, we need to copy it
    mlsClient.createGroup(
      Config.cipherSuite,
      signatureKeyPairs.computeIfAbsent(Config.cipherSuite, CipherSuite::generateSignatureKeyPair).copy(),
      credential,
      leafNodeExtensions =
        listOf(
          ApplicationId(applicationId.toBytes()),
        ),
    ).onRight {
      DeliveryService.registerForGroup(it.groupId, userName)
    }

  suspend fun joinPublicGroup(groupId: GroupId): Either<ExternalJoinError, ActiveGroupClient<String>> =
    mlsClient.joinFromGroupInfo(
      DeliveryService.getPublicGroupInfo(groupId).getOrThrow(),
      signatureKeyPairs.computeIfAbsent(Config.cipherSuite, CipherSuite::generateSignatureKeyPair).copy(),
      credential,
      leafNodeExtensions =
        listOf(
          ApplicationId(applicationId.toBytes()),
        ),
    ).map { (group, commit) ->
      DeliveryService.sendMessageToGroup(commit, groupId)
      DeliveryService.registerForGroup(group.groupId, userName)

      group
    }

  suspend fun sendMessage(
    to: GroupId,
    message: String,
  ) {
    DeliveryService.sendMessageToGroup(
      (mlsClient[to]!! as ActiveGroupClient<String>).seal(ApplicationData(message.encodeToByteArray())).getOrThrow(),
      to,
      fromUser = userName,
    )
  }

  suspend fun processNextMessage(): Either<Any, GroupClient<String, *>?> =
    either {
      messages.tryReceive().getOrNull()?.let { (messageId, encoded) ->
        println("[$userName] Message received: $messageId")

        when (val res = mlsClient.processMessage(encoded).bind()) {
          is ProcessMessageResult.WelcomeMessageReceived -> {
            val keyPackage = res.welcome.secrets.firstNotNullOf { getKeyPackage(it.newMember) }

            mlsClient.joinFromWelcome(res.welcome, keyPackage).bind().also {
              DeliveryService.registerForGroup(it.groupId, userName)
            }
          }

          is ProcessMessageResult.GroupInfoMessageReceived -> {
            mlsClient.joinFromGroupInfo(
              res.groupInfo,
              signatureKeyPairs.computeIfAbsent(Config.cipherSuite, CipherSuite::generateSignatureKeyPair),
              credential,
              leafNodeExtensions =
                listOf(
                  ApplicationId(applicationId.toBytes()),
                ),
            ).map { (group, commit) ->
              DeliveryService.sendMessageToGroup(commit, group.groupId)
              DeliveryService.registerForGroup(group.groupId, userName)

              group
            }.bind()
          }

          is ProcessMessageResult.ApplicationMessageReceived -> {
            println("[$userName] ${res.applicationData.framedContent.content.bytes.decodeToString()}")
            mlsClient[res.groupId]
          }

          is ProcessMessageResult.HandshakeMessageReceived -> {
            when (val handshakeResult = res.result) {
              is ProcessHandshakeResult.ProposalReceived, is ProcessHandshakeResult.CommitProcessed -> {
                println("[$userName] ${res.result}")
                mlsClient[res.groupId]
              }

              is ProcessHandshakeResult.CommitProcessedWithNewMembers -> {
                println("[$userName] CommitProcessed, adding new members")

                handshakeResult.welcomeMessages.forEach { (welcome, to) ->
                  DeliveryService.sendMessageToIdentities(
                    welcome.encoded,
                    authenticateCredentials(
                      to.map { it.leafNode.signaturePublicKey to it.leafNode.credential },
                    ).bindAll(),
                  )
                }

                mlsClient[res.groupId]
              }

              is ProcessHandshakeResult.ReInitProcessed -> {
                println("[$userName] ReInit processed, returning suspended group")
                handshakeResult.suspendedClient
              }
            }
          }

          is ProcessMessageResult.KeyPackageMessageReceived -> {
            println("Key package received, ignoring")
            null
          }
        }
      }
    }

  fun getKeyPackage(ref: KeyPackage.Ref): KeyPackage.Private? = keyPackages[ref.hex]

  suspend fun getKeyPackageFor(
    cipherSuite: CipherSuite,
    user: String,
  ): KeyPackage = DeliveryService.getKeyPackage(ProtocolVersion.MLS_1_0, cipherSuite, user).getOrThrow()

  context(Raise<CreateSignatureError>)
  fun newKeyPackage(cipherSuite: CipherSuite): KeyPackage.Private =
    // As this function takes ownership of the signature private key, we need to copy it
    mlsClient.newKeyPackage(
      cipherSuite,
      signatureKeyPairs.computeIfAbsent(cipherSuite, CipherSuite::generateSignatureKeyPair).copy(),
      credential,
      leafNodeExtensions =
        listOf(
          ApplicationId(applicationId.toBytes()),
        ),
    ).bind().also {
      keyPackages[it.ref.hex] = it
    }
}

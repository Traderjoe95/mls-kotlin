package com.github.traderjoe95.mls.protocol.client

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.CreateSignatureError
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.ExternalJoinError
import com.github.traderjoe95.mls.protocol.error.ExternalPskError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.GroupSuspended
import com.github.traderjoe95.mls.protocol.error.ProcessMessageError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.PublicMessageError
import com.github.traderjoe95.mls.protocol.error.UnknownGroup
import com.github.traderjoe95.mls.protocol.error.WelcomeJoinError
import com.github.traderjoe95.mls.protocol.group.resumption.isProtocolResumption
import com.github.traderjoe95.mls.protocol.message.ApplicationMessage
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.GroupMessage
import com.github.traderjoe95.mls.protocol.message.HandshakeMessage
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.ensureFormat
import com.github.traderjoe95.mls.protocol.message.PublicMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.psk.ExternalPskHolder
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtensions
import com.github.traderjoe95.mls.protocol.types.LeafNodeExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import com.github.traderjoe95.mls.protocol.util.hex

class MlsClient<Identity : Any>(
  val authenticationService: AuthenticationService<Identity>,
) : ExternalPskHolder<MlsClient<Identity>> {
  private val groups: MutableMap<String, GroupClient<Identity, *>> = mutableMapOf()
  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()

  fun createGroup(
    cipherSuite: CipherSuite,
    signatureKeyPair: SignatureKeyPair,
    credential: Credential,
    groupId: GroupId? = null,
    capabilities: Capabilities = Capabilities.default(),
    keyPackageExtensions: KeyPackageExtensions = listOf(),
    leafNodeExtensions: LeafNodeExtensions = listOf(),
  ): Either<GroupCreationError, ActiveGroupClient<Identity>> =
    either {
      GroupClient.newGroup(
        this@MlsClient,
        KeyPackage
          .generate(
            cipherSuite,
            signatureKeyPair.move(),
            credential,
            capabilities = capabilities,
            lifetime = Lifetime.always(),
            keyPackageExtensions = keyPackageExtensions,
            leafNodeExtensions = leafNodeExtensions,
          )
          .bind(),
        groupId = groupId,
      ).bind()
    }

  suspend fun joinFromWelcome(
    welcome: Welcome,
    ownKeyPackage: KeyPackage.Private,
    optionalTree: PublicRatchetTree? = null,
  ): Either<WelcomeJoinError, ActiveGroupClient<Identity>> =
    either {
      val resumingFrom =
        welcome.decryptGroupSecrets(ownKeyPackage)
          .bind()
          .preSharedKeyIds
          .filterIsInstance<ResumptionPskId>()
          .find { it.isProtocolResumption }
          ?.let {
            groups[it.pskGroupId.hex]
              ?.getStateForEpoch(it.pskGroupId, it.pskEpoch)
              ?: raise(WelcomeJoinError.MissingResumptionGroup(it))
          }

      GroupClient.joinFromWelcome(
        this@MlsClient,
        welcome,
        ownKeyPackage,
        resumingFrom,
        optionalTree,
      ).bind().also { register(it) }
    }

  suspend fun joinFromGroupInfo(
    groupInfo: GroupInfo,
    signatureKeyPair: SignatureKeyPair,
    credential: Credential,
    lifetime: Lifetime = Lifetime.always(),
    capabilities: Capabilities = Capabilities.default(),
    keyPackageExtensions: KeyPackageExtensions = listOf(),
    leafNodeExtensions: LeafNodeExtensions = listOf(),
    commitAuthenticatedData: ByteArray = byteArrayOf(),
    optionalTree: PublicRatchetTree? = null,
  ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
    either {
      joinFromGroupInfo(
        groupInfo,
        newKeyPackage(
          groupInfo.groupContext.cipherSuite,
          signatureKeyPair,
          credential,
          lifetime,
          capabilities,
          keyPackageExtensions,
          leafNodeExtensions,
        ).bind(),
        commitAuthenticatedData,
        optionalTree,
      ).bind()
    }

  suspend fun joinFromGroupInfo(
    groupInfo: GroupInfo,
    ownKeyPackage: KeyPackage.Private,
    commitAuthenticatedData: ByteArray = byteArrayOf(),
    optionalTree: PublicRatchetTree? = null,
  ): Either<ExternalJoinError, Pair<ActiveGroupClient<Identity>, ByteArray>> =
    GroupClient.joinFromGroupInfo(
      this@MlsClient,
      groupInfo,
      ownKeyPackage,
      commitAuthenticatedData,
      optionalTree,
    ).onRight { (client, _) -> register(client) }

  @JvmOverloads
  fun newKeyPackage(
    cipherSuite: CipherSuite,
    signatureKeyPair: SignatureKeyPair,
    credential: Credential,
    lifetime: Lifetime = Lifetime.always(),
    capabilities: Capabilities = Capabilities.default(),
    keyPackageExtensions: KeyPackageExtensions = listOf(),
    leafNodeExtensions: LeafNodeExtensions = listOf(),
  ): Either<CreateSignatureError, KeyPackage.Private> =
    KeyPackage
      .generate(
        cipherSuite,
        signatureKeyPair.move(),
        credential,
        capabilities,
        lifetime,
        keyPackageExtensions,
        leafNodeExtensions,
      )

  fun decodeMessage(messageBytes: ByteArray): Either<DecoderError, MlsMessage<*>> = GroupClient.decodeMessage(messageBytes)

  suspend fun processMessage(messageBytes: ByteArray): Either<ProcessMessageError, ProcessMessageResult<Identity>> =
    decodeMessage(messageBytes)
      .flatMap { processMessage(it) }

  suspend fun processMessage(message: MlsMessage<*>): Either<ProcessMessageError, ProcessMessageResult<Identity>> =
    either {
      when (message.message) {
        is KeyPackage -> ProcessMessageResult.KeyPackageMessageReceived(message.message)
        is Welcome -> ProcessMessageResult.WelcomeMessageReceived(message.message)
        is GroupInfo -> ProcessMessageResult.GroupInfoMessageReceived(message.message)
        is GroupMessage<*> -> processGroupMessage(message.message).bind()
      }
    }

  suspend fun processGroupMessage(groupMessageBytes: ByteArray): Either<ProcessMessageError, ProcessMessageResult<Identity>> =
    either {
      val msg = decodeMessage(groupMessageBytes).bind().ensureFormat<GroupMessage<*>>()
      processGroupMessage(msg.message).bind()
    }

  @Suppress("UNCHECKED_CAST")
  suspend fun processGroupMessage(groupMessage: GroupMessage<*>): Either<ProcessMessageError, ProcessMessageResult<Identity>> =
    either {
      val groupId = groupMessage.groupId
      val group = groups[groupId.hex] ?: raise(UnknownGroup(groupId))

      when (groupMessage.contentType) {
        is ContentType.Handshake ->
          if (group is ActiveGroupClient<Identity>) {
            ProcessMessageResult.HandshakeMessageReceived(
              groupId,
              group.processHandshake(groupMessage as HandshakeMessage).bind(),
            )
          } else {
            raise(GroupSuspended(groupMessage.groupId))
          }

        is ContentType.Application ->
          if (groupMessage is PublicMessage) {
            raise(PublicMessageError.ApplicationMessageMustNotBePublic)
          } else {
            ProcessMessageResult.ApplicationMessageReceived(
              groupId,
              group.open(groupMessage as ApplicationMessage).bind(),
            )
          }

        else ->
          error("unreachable")
      }
    }

  operator fun get(groupId: GroupId): GroupClient<Identity, *>? = groups[groupId.hex]

  override fun registerExternalPsk(
    pskId: ByteArray,
    psk: Secret,
  ): MlsClient<Identity> =
    apply {
      externalPsks[pskId.hex] = psk
    }

  override fun deleteExternalPsk(pskId: ByteArray): MlsClient<Identity> = apply { externalPsks.remove(pskId.hex) }

  override fun clearExternalPsks(): MlsClient<Identity> = apply { externalPsks.clear() }

  override suspend fun getPreSharedKey(id: PreSharedKeyId): Either<PskError, Secret> =
    either {
      when (id) {
        is ExternalPskId -> externalPsks[id.pskId.hex] ?: raise(ExternalPskError.UnknownExternalPsk(id.pskId))
        is ResumptionPskId ->
          groups[id.pskGroupId.hex]?.getPreSharedKey(id)?.bind()
            ?: raise(UnknownGroup(id.pskGroupId))
      }
    }

  internal fun register(groupClient: GroupClient<Identity, *>) {
    groups[groupClient.groupId.hex] = groupClient
  }
}

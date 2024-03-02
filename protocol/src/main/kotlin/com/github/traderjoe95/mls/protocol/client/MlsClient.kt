package com.github.traderjoe95.mls.protocol.client

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.CreateSignatureError
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.ExternalPskError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.UnknownGroup
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.psk.ExternalPskHolder
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtensions
import com.github.traderjoe95.mls.protocol.types.LeafNodeExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import com.github.traderjoe95.mls.protocol.util.hex

class MlsClient<Identity : Any>(
  val authenticationService: AuthenticationService<Identity>,
) : ExternalPskHolder<MlsClient<Identity>> {
  private val groups: MutableMap<String, ActiveGroupClient<Identity>> = mutableMapOf()
  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()
  private val keyPackages: MutableMap<String, KeyPackage.Private> = mutableMapOf()

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
      ActiveGroupClient.newGroup(
        generateKeyPackage(
          cipherSuite,
          signatureKeyPair.move(),
          credential,
          capabilities = capabilities,
          keyPackageExtensions = keyPackageExtensions,
          leafNodeExtensions = leafNodeExtensions,
        ),
        authenticationService,
        groupId = groupId,
      ).bind()
    }

  @JvmOverloads
  fun newKeyPackage(
    cipherSuite: CipherSuite,
    signatureKeyPair: SignatureKeyPair,
    credential: Credential,
    lifetime: Lifetime = Lifetime.always(),
    capabilities: Capabilities = Capabilities.default(),
    keyPackageExtensions: KeyPackageExtensions = listOf(),
    leafNodeExtensions: LeafNodeExtensions = listOf(),
  ): Either<CreateSignatureError, KeyPackage> =
    either {
      generateKeyPackage(
        cipherSuite,
        signatureKeyPair.move(),
        credential,
        lifetime,
        capabilities,
        keyPackageExtensions,
        leafNodeExtensions,
        store = true,
      ).public
    }

  context(Raise<CreateSignatureError>)
  private fun generateKeyPackage(
    cipherSuite: CipherSuite,
    signatureKeyPair: SignatureKeyPair,
    credential: Credential,
    lifetime: Lifetime = Lifetime.always(),
    capabilities: Capabilities = Capabilities.default(),
    keyPackageExtensions: KeyPackageExtensions = listOf(),
    leafNodeExtensions: LeafNodeExtensions = listOf(),
    store: Boolean = false,
  ): KeyPackage.Private =
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
      .bind()
      .also { if (store) keyPackages[cipherSuite.makeKeyPackageRef(it.public).hex] = it }

  fun decodeMessage(messageBytes: ByteArray): Either<DecoderError, MlsMessage<*>> = ActiveGroupClient.decodeMessage(messageBytes)

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
        is ResumptionPskId -> groups[id.pskGroupId.hex]?.getPreSharedKey(id)?.bind() ?: raise(UnknownGroup(id.pskGroupId))
      }
    }
}

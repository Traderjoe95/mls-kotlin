package com.github.traderjoe95.mls.protocol.client

import arrow.core.Either
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.ExternalPskError
import com.github.traderjoe95.mls.protocol.error.GroupCreationError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.error.UnknownGroup
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.KeyPackage.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
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
) : PskLookup {
  private val groups: MutableMap<String, GroupClient<Identity>> = mutableMapOf()
  private val externalPsks: MutableMap<String, Secret> = mutableMapOf()
  private val keyPackages: MutableMap<String, KeyPackage.Private> = mutableMapOf()

  fun createGroup(
    cipherSuite: CipherSuite,
    signatureKeyPair: SignatureKeyPair,
    credential: Credential,
    groupId: GroupId = GroupId.new(),
    capabilities: Capabilities = Capabilities.default(),
    keyPackageExtensions: KeyPackageExtensions = listOf(),
    leafNodeExtensions: LeafNodeExtensions = listOf(),
  ): Either<GroupCreationError, GroupClient<Identity>> = TODO()

  fun newKeyPackage(
    cipherSuite: CipherSuite,
    signatureKeyPair: SignatureKeyPair,
    credential: Credential,
    lifetime: Lifetime = Lifetime.always(),
    capabilities: Capabilities = Capabilities.default(),
    keyPackageExtensions: KeyPackageExtensions = listOf(),
    leafNodeExtensions: LeafNodeExtensions = listOf(),
  ): ByteArray =
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
      .also { keyPackages[cipherSuite.makeKeyPackageRef(it.public).hex] = it }
      .public
      .encodeUnsafe()

  fun registerExternalPsk(
    pskId: ByteArray,
    psk: Secret,
  ): MlsClient<Identity> =
    apply {
      externalPsks[pskId.hex] = psk
    }

  fun deleteExternalPsk(pskId: ByteArray): MlsClient<Identity> = apply { externalPsks.remove(pskId.hex) }

  fun clearExternalPsks(): MlsClient<Identity> = apply { externalPsks.clear() }

  context(Raise<PskError>)
  override suspend fun getPreSharedKey(id: PreSharedKeyId): Secret =
    when (id) {
      is ExternalPskId -> externalPsks[id.pskId.hex] ?: raise(ExternalPskError.UnknownExternalPsk(id.pskId))
      is ResumptionPskId -> groups[id.pskGroupId.hex]?.getPreSharedKey(id) ?: raise(UnknownGroup(id.pskGroupId))
    }
}

package com.github.traderjoe95.mls.protocol.interop.message

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getHpkePrivateKey
import com.github.traderjoe95.mls.protocol.interop.util.getSignaturePublicKey
import com.github.traderjoe95.mls.protocol.message.EncryptedGroupSecrets
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.GroupInfo.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.message.GroupSecrets
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.CredentialType
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Aad
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextUInt
import kotlin.random.nextULong
import kotlin.time.Duration.Companion.hours

data class WelcomeTestVector(
  val cipherSuite: CipherSuite,
  val initPriv: HpkePrivateKey,
  val signerPub: SignaturePublicKey,
  val keyPackage: MlsMessage<KeyPackage>,
  val welcome: MlsMessage<Welcome>,
) {
  @Suppress("UNCHECKED_CAST")
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getHpkePrivateKey("init_priv"),
    json.getSignaturePublicKey("signer_pub"),
    MlsMessage.decodeUnsafe(json.getHexBinary("key_package")) as MlsMessage<KeyPackage>,
    MlsMessage.decodeUnsafe(json.getHexBinary("welcome")) as MlsMessage<Welcome>,
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/welcome.json",
    ): List<WelcomeTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { WelcomeTestVector(it as JsonObject) }

    fun generate(cipherSuite: CipherSuite): WelcomeTestVector {
      val sigKeyPair = cipherSuite.generateSignatureKeyPair()
      val keyPackagePrivate =
        KeyPackage.generate(
          cipherSuite,
          sigKeyPair,
          BasicCredential(Random.nextBytes(64)),
          Capabilities.create(listOf(CredentialType.Basic)),
          5.hours,
        )

      val cth = Random.nextBytes(cipherSuite.hashLen.toInt())

      val groupContext =
        GroupContext(
          ProtocolVersion.MLS_1_0,
          cipherSuite,
          GroupId.new(),
          Random.nextULong(),
          Random.nextBytes(cipherSuite.hashLen.toInt()),
          cth,
        )

      val pskSecret = Secret.zeroes(cipherSuite.hashLen)
      val joinerSecret = cipherSuite.generateSecret(cipherSuite.hashLen)
      val joinerExtracted = cipherSuite.extract(joinerSecret, pskSecret)
      val welcomeSecret = cipherSuite.deriveSecret(joinerExtracted, "welcome")
      val keySchedule =
        KeySchedule.join(
          cipherSuite,
          joinerSecret,
          pskSecret,
          groupContext,
        )

      val groupInfo =
        GroupInfo.create(
          LeafIndex(Random.nextUInt()),
          sigKeyPair.private,
          groupContext,
          cipherSuite.mac(keySchedule.confirmationKey, cth),
        )
      val welcomeNonce =
        cipherSuite.expandWithLabel(welcomeSecret, "nonce", byteArrayOf(), cipherSuite.nonceLen).asNonce
      val welcomeKey = cipherSuite.expandWithLabel(welcomeSecret, "key", byteArrayOf(), cipherSuite.keyLen)
      val encryptedGroupInfo = cipherSuite.encryptAead(welcomeKey, welcomeNonce, Aad.empty, groupInfo.encodeUnsafe())

      val groupSecrets = GroupSecrets(joinerSecret)
      val encryptedGroupSecrets =
        groupSecrets.generateEncrypted(cipherSuite, encryptedGroupInfo) +
          groupSecrets.encrypt(cipherSuite, keyPackagePrivate.public, encryptedGroupInfo) +
          groupSecrets.generateEncrypted(cipherSuite, encryptedGroupInfo)

      return WelcomeTestVector(
        cipherSuite,
        keyPackagePrivate.initPrivateKey,
        sigKeyPair.public,
        MlsMessage.keyPackage(keyPackagePrivate.public),
        MlsMessage.welcome(cipherSuite, encryptedGroupSecrets, encryptedGroupInfo),
      )
    }

    private fun GroupSecrets.generateEncrypted(
      cipherSuite: CipherSuite,
      encryptedGroupInfo: Ciphertext,
    ): List<EncryptedGroupSecrets> =
      List(Random.nextInt(0..3)) {
        val otherKp =
          KeyPackage.generate(
            cipherSuite,
            cipherSuite.generateSignatureKeyPair(),
            BasicCredential(Random.nextBytes(64)),
            Capabilities.create(listOf(CredentialType.Basic)),
            5.hours,
          )

        encrypt(cipherSuite, otherKp.public, encryptedGroupInfo)
      }
  }
}

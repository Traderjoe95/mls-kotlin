package com.github.traderjoe95.mls.protocol.interop.group

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinaryOrNull
import com.github.traderjoe95.mls.protocol.interop.util.getHpkePrivateKey
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.getSignaturePrivateKey
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsCommitMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.coerceFormat
import com.github.traderjoe95.mls.protocol.message.MlsProposalMessage
import com.github.traderjoe95.mls.protocol.message.Welcome
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait

data class PassiveClientTestVector(
  val cipherSuite: CipherSuite,
  val externalPsks: List<ExternalPsk>,
  // Initial client info
  val keyPackage: MlsMessage<KeyPackage>,
  val signaturePriv: SignaturePrivateKey,
  val encryptionPriv: HpkePrivateKey,
  val initPriv: HpkePrivateKey,
  // Joining
  val welcome: MlsMessage<Welcome>,
  val ratchetTree: PublicRatchetTree?,
  val initialEpochAuthenticator: Secret,
  // Epochs
  val epochs: List<GroupEpoch>,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getJsonArray("external_psks").map { ExternalPsk(it as JsonObject) },
    MlsMessage.decodeUnsafe(json.getHexBinary("key_package")).coerceFormat(),
    json.getSignaturePrivateKey("signature_priv"),
    json.getHpkePrivateKey("encryption_priv"),
    json.getHpkePrivateKey("init_priv"),
    MlsMessage.decodeUnsafe(json.getHexBinary("welcome")).coerceFormat(),
    json.getHexBinaryOrNull("ratchet_tree")?.let { PublicRatchetTree.decodeUnsafe(it) },
    json.getSecret("initial_epoch_authenticator"),
    json.getJsonArray("epochs").map { GroupEpoch(it as JsonObject) },
  )

  val privateKeyPackage: KeyPackage.Private
    get() = KeyPackage.Private(keyPackage.message, initPriv, encryptionPriv, signaturePriv)

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String,
    ): List<PassiveClientTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { PassiveClientTestVector(it as JsonObject) }
  }

  data class ExternalPsk(val pskId: ByteArray, val psk: Secret) {
    constructor(json: JsonObject) : this(json.getHexBinary("psk_id"), json.getSecret("psk"))
  }

  data class GroupEpoch(
    val proposals: List<MlsProposalMessage<*>>,
    val commit: MlsCommitMessage<*>,
    val epochAuthenticator: Secret,
  ) {
    @OptIn(ExperimentalStdlibApi::class)
    constructor(json: JsonObject) : this(
      json.getJsonArray("proposals").map {
        MlsMessage.decodeUnsafe((it as String).hexToByteArray()).coerceFormat()
      },
      MlsCommitMessage.decodeUnsafe(json.getHexBinary("commit")).coerceFormat(),
      json.getSecret("epoch_authenticator"),
    )
  }
}

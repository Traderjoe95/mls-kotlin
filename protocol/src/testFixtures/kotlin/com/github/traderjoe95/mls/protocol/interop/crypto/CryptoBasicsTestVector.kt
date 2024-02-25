package com.github.traderjoe95.mls.protocol.interop.crypto

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getCiphertext
import com.github.traderjoe95.mls.protocol.interop.util.getHashReference
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getHpkePrivateKey
import com.github.traderjoe95.mls.protocol.interop.util.getHpkePublicKey
import com.github.traderjoe95.mls.protocol.interop.util.getKemOutput
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.getSignature
import com.github.traderjoe95.mls.protocol.interop.util.getSignaturePrivateKey
import com.github.traderjoe95.mls.protocol.interop.util.getSignaturePublicKey
import com.github.traderjoe95.mls.protocol.interop.util.getUInt
import com.github.traderjoe95.mls.protocol.interop.util.getUShort
import com.github.traderjoe95.mls.protocol.interop.util.nextString
import com.github.traderjoe95.mls.protocol.interop.util.nextUShort
import com.github.traderjoe95.mls.protocol.tree.Ratchet.Companion.deriveTreeSecret
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.core.json.get
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.random.nextUInt

@OptIn(ExperimentalStdlibApi::class)
data class CryptoBasicsTestVector(
  val cipherSuite: CipherSuite,
  val refHash: RefHash,
  val expandWithLabel: ExpandWithLabel,
  val deriveSecret: DeriveSecret,
  val deriveTreeSecret: DeriveTreeSecret,
  val signWithLabel: SignWithLabel,
  val encryptWithLabel: EncryptWithLabel,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    RefHash(json["ref_hash"]),
    ExpandWithLabel(json["expand_with_label"]),
    DeriveSecret(json["derive_secret"]),
    DeriveTreeSecret(json["derive_tree_secret"]),
    SignWithLabel(json["sign_with_label"]),
    EncryptWithLabel(json["encrypt_with_label"]),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/crypto-basics.json",
    ): List<CryptoBasicsTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { CryptoBasicsTestVector(it as JsonObject) }

    fun generate(cipherSuite: CipherSuite): CryptoBasicsTestVector =
      CryptoBasicsTestVector(
        cipherSuite,
        RefHash.generate(cipherSuite),
        ExpandWithLabel.generate(cipherSuite),
        DeriveSecret.generate(cipherSuite),
        DeriveTreeSecret.generate(cipherSuite),
        SignWithLabel.generate(cipherSuite),
        EncryptWithLabel.generate(cipherSuite),
      )
  }

  data class RefHash(val label: String, val value: ByteArray, val out: HashReference) {
    constructor(json: JsonObject) : this(
      json["label"],
      json.getHexBinary("value"),
      json.getHashReference("out"),
    )

    companion object {
      fun generate(cipherSuite: CipherSuite): RefHash {
        val label = Random.nextString()
        val value = Random.nextBytes(Random.nextInt(0..1024))

        return RefHash(
          label,
          value,
          cipherSuite.refHash(label, value),
        )
      }
    }
  }

  data class ExpandWithLabel(
    val secret: Secret,
    val label: String,
    val context: ByteArray,
    val length: UShort,
    val out: Secret,
  ) {
    constructor(json: JsonObject) : this(
      json.getSecret("secret"),
      json["label"],
      json.getHexBinary("context"),
      json.getUShort("length"),
      json.getSecret("out"),
    )

    companion object {
      fun generate(cipherSuite: CipherSuite): ExpandWithLabel =
        cipherSuite.generateSecret(Random.nextUShort(16U..128U)).let { secret ->
          val label = Random.nextString()
          val context = Random.nextBytes(Random.nextInt(0..128))
          val length = Random.nextUShort(16U..128U)

          ExpandWithLabel(
            secret,
            label,
            context,
            length,
            cipherSuite.expandWithLabel(secret, label, context, length),
          )
        }
    }
  }

  data class DeriveSecret(
    val secret: Secret,
    val label: String,
    val out: Secret,
  ) {
    constructor(json: JsonObject) : this(
      json.getSecret("secret"),
      json["label"],
      json.getSecret("out"),
    )

    companion object {
      fun generate(cipherSuite: CipherSuite): DeriveSecret =
        cipherSuite.generateSecret(Random.nextUShort(16U..128U)).let { secret ->
          val label = Random.nextString()

          DeriveSecret(
            secret,
            label,
            cipherSuite.deriveSecret(secret, label),
          )
        }
    }
  }

  data class DeriveTreeSecret(
    val secret: Secret,
    val label: String,
    val generation: UInt,
    val length: UShort,
    val out: Secret,
  ) {
    constructor(json: JsonObject) : this(
      json.getSecret("secret"),
      json["label"],
      json.getUInt("generation"),
      json.getUShort("length"),
      json.getSecret("out"),
    )

    companion object {
      fun generate(cipherSuite: CipherSuite): DeriveTreeSecret =
        cipherSuite.generateSecret(cipherSuite.hashLen).let { secret ->
          val label = Random.nextString()
          val generation = Random.nextUInt()
          val length = Random.nextUShort(16U..128U)

          DeriveTreeSecret(
            secret,
            label,
            generation,
            length,
            cipherSuite.deriveTreeSecret(secret, label, generation, length),
          )
        }
    }
  }

  data class SignWithLabel(
    val priv: SignaturePrivateKey,
    val pub: SignaturePublicKey,
    val content: ByteArray,
    val label: String,
    val signature: Signature,
  ) {
    constructor(json: JsonObject) : this(
      json.getSignaturePrivateKey("priv"),
      json.getSignaturePublicKey("pub"),
      json.getHexBinary("content"),
      json["label"],
      json.getSignature("signature"),
    )

    companion object {
      fun generate(cipherSuite: CipherSuite): SignWithLabel =
        cipherSuite.generateSignatureKeyPair().let { (private, public) ->
          val content = Random.nextBytes(Random.nextInt(0..1024))
          val label = Random.nextString()

          SignWithLabel(
            private,
            public,
            content,
            label,
            cipherSuite.signWithLabel(private, label, content),
          )
        }
    }
  }

  data class EncryptWithLabel(
    val priv: HpkePrivateKey,
    val pub: HpkePublicKey,
    val label: String,
    val context: ByteArray,
    val plaintext: ByteArray,
    val kemOutput: KemOutput,
    val ciphertext: Ciphertext,
  ) {
    val keyPair: HpkeKeyPair
      get() = HpkeKeyPair(priv to pub)

    val hpkeCiphertext: HpkeCiphertext
      get() = HpkeCiphertext(kemOutput, ciphertext)

    constructor(json: JsonObject) : this(
      json.getHpkePrivateKey("priv"),
      json.getHpkePublicKey("pub"),
      json["label"],
      json.getHexBinary("context"),
      json.getHexBinary("plaintext"),
      json.getKemOutput("kem_output"),
      json.getCiphertext("ciphertext"),
    )

    companion object {
      fun generate(cipherSuite: CipherSuite): EncryptWithLabel =
        cipherSuite.generateHpkeKeyPair().let { (private, public) ->
          val label = Random.nextString()
          val context = Random.nextBytes(Random.nextInt(0..128))
          val plaintext = Random.nextBytes(Random.nextInt(0..1024))

          val (kemOutput, ciphertext) = cipherSuite.encryptWithLabel(public, label, context, plaintext)

          EncryptWithLabel(
            private,
            public,
            label,
            context,
            plaintext,
            kemOutput,
            ciphertext,
          )
        }
    }
  }
}

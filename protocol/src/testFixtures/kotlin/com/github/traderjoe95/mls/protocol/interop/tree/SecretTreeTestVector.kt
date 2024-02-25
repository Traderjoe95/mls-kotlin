package com.github.traderjoe95.mls.protocol.interop.tree

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.getSenderDataNonceAndKey
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getCiphertext
import com.github.traderjoe95.mls.protocol.interop.util.getNonce
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.getUInt
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext.Companion.asCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.core.json.get
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextInt

@OptIn(ExperimentalStdlibApi::class)
data class SecretTreeTestVector(
  val cipherSuite: CipherSuite,
  val senderData: SenderData,
  val encryptionSecret: Secret,
  val leaves: List<List<LeafGeneration>>,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    SenderData(json["sender_data"]),
    json.getSecret("encryption_secret"),
    json.getJsonArray("leaves").map {
      when (it) {
        is Iterable<*> -> it.map { LeafGeneration(it as JsonObject) }
        else -> error("Invalid type inside 'leaves'")
      }
    },
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/secret-tree.json",
    ): List<SecretTreeTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { SecretTreeTestVector(it as JsonObject) }

    suspend fun generate(
      cipherSuite: CipherSuite,
      leafCount: UInt,
      generations: Set<UInt>,
    ): SecretTreeTestVector {
      val encryptionSecret = cipherSuite.generateSecret(cipherSuite.hashLen)

      return SecretTreeTestVector(
        cipherSuite,
        SenderData.generate(cipherSuite),
        encryptionSecret,
        LeafGeneration.generate(cipherSuite, leafCount, encryptionSecret.copy(), generations),
      )
    }
  }

  data class SenderData(
    val senderDataSecret: Secret,
    val ciphertext: Ciphertext,
    val key: Secret,
    val nonce: Nonce,
  ) {
    constructor(json: JsonObject) : this(
      json.getSecret("sender_data_secret"),
      json.getCiphertext("ciphertext"),
      json.getSecret("key"),
      json.getNonce("nonce"),
    )

    companion object {
      fun generate(cipherSuite: CipherSuite): SenderData =
        cipherSuite.generateSecret(cipherSuite.hashLen).let { senderDataSecret ->
          val ciphertext = Random.nextBytes(Random.nextInt(1..2 * cipherSuite.hashLen.toInt())).asCiphertext
          val (nonce, key) = cipherSuite.getSenderDataNonceAndKey(senderDataSecret, ciphertext)

          SenderData(
            senderDataSecret,
            ciphertext,
            key,
            nonce,
          )
        }
    }
  }

  data class LeafGeneration(
    val generation: UInt,
    val handshakeKey: Secret,
    val handshakeNonce: Nonce,
    val applicationKey: Secret,
    val applicationNonce: Nonce,
  ) {
    constructor(json: JsonObject) : this(
      json.getUInt("generation"),
      json.getSecret("handshake_key"),
      json.getNonce("handshake_nonce"),
      json.getSecret("application_key"),
      json.getNonce("application_nonce"),
    )

    companion object {
      suspend fun generate(
        cipherSuite: CipherSuite,
        leafCount: UInt,
        encryptionSecret: Secret,
        generations: Set<UInt>,
      ): List<List<LeafGeneration>> =
        SecretTree.create(cipherSuite, encryptionSecret, leafCount).let { tree ->
          val sortedGenerations = generations.sorted()

          return (0U..<leafCount).map { leafIdx ->
            sortedGenerations.map { gen ->
              val (handshakeNonce, handshakeKey) =
                unsafe {
                  tree.getNonceAndKey(LeafIndex(leafIdx), ContentType.Commit, gen)
                }
              val (applicationNonce, applicationKey) =
                unsafe {
                  tree.getNonceAndKey(LeafIndex(leafIdx), ContentType.Application, gen)
                }

              LeafGeneration(gen, handshakeKey, handshakeNonce, applicationKey, applicationNonce)
            }
          }
        }
    }
  }
}

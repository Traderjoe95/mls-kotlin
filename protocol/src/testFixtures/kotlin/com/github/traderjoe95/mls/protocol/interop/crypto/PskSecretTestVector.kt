package com.github.traderjoe95.mls.protocol.interop.crypto

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.calculatePskSecret
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getNonce
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.nextUShort
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce.Companion.asNonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random

data class PskSecretTestVector(
  val cipherSuite: CipherSuite,
  val psks: List<ExternalPsk>,
  val pskSecret: Secret,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getJsonArray("psks").map { ExternalPsk(it as JsonObject) },
    json.getSecret("psk_secret"),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/psk_secret.json",
    ): List<PskSecretTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { PskSecretTestVector(it as JsonObject) }

    fun generate(
      cipherSuite: CipherSuite,
      pskCount: UInt,
    ): PskSecretTestVector {
      val psks =
        List(pskCount.toInt()) {
          ExternalPsk(
            Random.nextBytes(32),
            cipherSuite.generateSecret(Random.nextUShort(16U..64U)),
            Random.nextBytes(cipherSuite.hashLen.toInt()).asNonce,
          )
        }
      val pskSecret =
        with(cipherSuite) {
          psks.map { ExternalPskId(it.pskId, it.pskNonce) to it.psk }.calculatePskSecret()
        }

      return PskSecretTestVector(cipherSuite, psks, pskSecret)
    }
  }

  data class ExternalPsk(
    val pskId: ByteArray,
    val psk: Secret,
    val pskNonce: Nonce,
  ) {
    constructor(json: JsonObject) : this(
      json.getHexBinary("psk_id"),
      json.getSecret("psk"),
      json.getNonce("psk_nonce"),
    )
  }
}

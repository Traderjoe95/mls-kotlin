package com.github.traderjoe95.mls.protocol.interop.codec

import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getUInt
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextUInt

data class DeserializationTestVector(
  val vlBytesHeader: ByteArray,
  val length: UInt,
) {
  constructor(json: JsonObject) : this(
    json.getHexBinary("vlbytes_header"),
    json.getUInt("length"),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/deserialization.json",
    ): List<DeserializationTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { DeserializationTestVector(it as JsonObject) }

    fun generate(): DeserializationTestVector =
      Random.nextUInt(0U..0x3FFFFFFFU).let {
        DeserializationTestVector(
          V(uint8).encodeUnsafe(it),
          it,
        )
      }
  }
}

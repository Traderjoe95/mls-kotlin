package com.github.traderjoe95.mls.protocol.codec

import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.uint8
import com.github.traderjoe95.mls.protocol.interop.codec.DeserializationTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking

class VariableLengthDeserialization : VertxFunSpec({ vertx ->
  val v = V(uint8)
  val testVectors =
    runBlocking { DeserializationTestVector.load(vertx) } + (1..200).map { DeserializationTestVector.generate() }

  testVectors
    .distinctBy { it.length }
    .sortedBy { it.length }
    .forEach { (header, length) ->
      context("For length $length") {
        test("The header should be decoded to the same length") {
          either { header.decodeAs(v) } shouldBeRight length
        }

        test("The length should be encoded to the same header bytes") {
          either { v.encode(length) } shouldBeRight header
        }
      }
    }
})

package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.interop.crypto.PskSecretTestVector
import com.github.traderjoe95.mls.protocol.psk.ResolvedPsk
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.testing.shouldBeEq
import com.github.traderjoe95.mls.protocol.util.hex
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import kotlin.random.Random
import kotlin.random.nextUInt

class PskSecret : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { PskSecretTestVector.load(vertx) } +
      CipherSuite.validEntries.map { PskSecretTestVector.generate(it, Random.nextUInt(0U..10U)) }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<PskSecretTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            test("for ${v.psks.size} PSKs the calculated PSK secret should be ${v.pskSecret.hex}") {
              ResolvedPsk.calculatePskSecret(
                cipherSuite,
                v.psks.map(PskSecretTestVector.ExternalPsk::asResolved),
              ) shouldBeEq v.pskSecret
            }
          }
        }
      }
  }
}

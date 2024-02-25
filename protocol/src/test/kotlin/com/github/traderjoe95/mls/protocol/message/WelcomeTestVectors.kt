package com.github.traderjoe95.mls.protocol.message

import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.interop.message.WelcomeTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.util.hex
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec

class WelcomeTestVectors : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { WelcomeTestVector.load(vertx) } +
      CipherSuite.validEntries.map { runBlocking { WelcomeTestVector.generate(it) } }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<WelcomeTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            test("should be able to decrypt a welcome message with init key ${v.initPriv.hex}") {
              val groupSecrets =
                either {
                  v.welcome.message.decryptGroupSecrets(
                    v.keyPackage.message.ref,
                    cipherSuite.reconstructPublicKey(v.initPriv),
                  )
                }.shouldBeRight()

              val pskSecret = Secret.zeroes(cipherSuite.hashLen)
              val groupInfo =
                either {
                  v.welcome.message.decryptGroupInfo(groupSecrets.joinerSecret, pskSecret)
                }.shouldBeRight()

              val keySchedule =
                KeySchedule.join(
                  cipherSuite,
                  groupSecrets.joinerSecret,
                  pskSecret,
                  groupInfo.groupContext,
                )

              either {
                cipherSuite.verifyMac(
                  keySchedule.confirmationKey,
                  groupInfo.groupContext.confirmedTranscriptHash,
                  groupInfo.confirmationTag,
                )
              }.shouldBeRight()
            }
          }
        }
      }
  }
}

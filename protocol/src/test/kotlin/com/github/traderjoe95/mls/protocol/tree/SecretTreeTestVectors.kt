package com.github.traderjoe95.mls.protocol.tree

import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.getSenderDataNonceAndKey
import com.github.traderjoe95.mls.protocol.interop.tree.SecretTreeTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.util.hex
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.shouldBe

class SecretTreeTestVectors : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { SecretTreeTestVector.load(vertx) } +
      CipherSuite.validEntries.flatMap { cs ->
        listOf(1U, 2U, 4U, 8U, 16U, 32U).map { cs to it }
      }.map { (cs, leaves) ->
        runBlocking { SecretTreeTestVector.generate(cs, leaves, setOf(0U, 3U, 25U)) }
      }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<SecretTreeTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          context("should calculate correct Sender Data Nonce and Key") {
            testVectors.forEach { v ->
              test("for a sender data secret of '${v.senderData.senderDataSecret.hex}'") {
                val (nonce, key) =
                  cipherSuite.getSenderDataNonceAndKey(
                    v.senderData.senderDataSecret,
                    v.senderData.ciphertext,
                  )

                nonce.bytes shouldBe v.senderData.nonce.bytes
                key.bytes shouldBe v.senderData.key.bytes
              }
            }
          }

          context("should calculate correct values for the secret tree") {
            testVectors.forEach { v ->
              context("for an encryption secret of '${v.encryptionSecret.hex}'") {
                val secretTree = SecretTree.create(cipherSuite, v.encryptionSecret, v.leaves.uSize)

                v.leaves.forEachIndexed { idx, leaf ->
                  context("for leaf $idx") {
                    leaf.sortedBy { it.generation }.forEach { leafGen ->
                      test("and generation ${leafGen.generation}") {
                        val (hNonce, hKey) =
                          unsafe {
                            secretTree.getNonceAndKey(
                              LeafIndex(idx.toUInt()),
                              ContentType.Commit,
                              leafGen.generation,
                            )
                          }

                        val (aNonce, aKey) =
                          unsafe {
                            secretTree.getNonceAndKey(
                              LeafIndex(idx.toUInt()),
                              ContentType.Application,
                              leafGen.generation,
                            )
                          }

                        hNonce.bytes shouldBe leafGen.handshakeNonce.bytes
                        hKey.bytes shouldBe leafGen.handshakeKey.bytes

                        aNonce.bytes shouldBe leafGen.applicationNonce.bytes
                        aKey.bytes shouldBe leafGen.applicationKey.bytes
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
  }
}

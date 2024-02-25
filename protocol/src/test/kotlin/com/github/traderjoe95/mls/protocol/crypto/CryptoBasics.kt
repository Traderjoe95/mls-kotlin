package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.interop.crypto.CryptoBasicsTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.tree.Ratchet.Companion.deriveTreeSecret
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.checkAll
import io.kotest.property.exhaustive.exhaustive

class CryptoBasics : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { CryptoBasicsTestVector.load(vertx) } +
      CipherSuite.validEntries.map(CryptoBasicsTestVector::generate)

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<CryptoBasicsTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          context("RefHash") {
            test("should produce the expected results") {
              checkAll(exhaustive(testVectors)) { testVector ->
                cipherSuite.refHash(
                  testVector.refHash.label,
                  testVector.refHash.value,
                ).bytes shouldBe testVector.refHash.out.bytes
              }
            }
          }

          context("ExpandWithLabel") {
            test("should produce the expected secret") {
              checkAll(exhaustive(testVectors)) { testVector ->
                cipherSuite.expandWithLabel(
                  testVector.expandWithLabel.secret,
                  testVector.expandWithLabel.label,
                  testVector.expandWithLabel.context,
                  testVector.expandWithLabel.length,
                ).bytes shouldBe testVector.expandWithLabel.out.bytes
              }
            }
          }

          context("DeriveSecret") {
            test("should produce the expected secret") {
              checkAll(exhaustive(testVectors)) { testVector ->
                cipherSuite.deriveSecret(
                  testVector.deriveSecret.secret,
                  testVector.deriveSecret.label,
                ).bytes shouldBe testVector.deriveSecret.out.bytes
              }
            }
          }

          context("DeriveTreeSecret") {
            test("should produce the expected secret") {
              checkAll(exhaustive(testVectors)) { testVector ->
                cipherSuite.deriveTreeSecret(
                  testVector.deriveTreeSecret.secret,
                  testVector.deriveTreeSecret.label,
                  testVector.deriveTreeSecret.generation,
                  testVector.deriveTreeSecret.length,
                ).bytes shouldBe testVector.deriveTreeSecret.out.bytes
              }
            }
          }

          context("SignWithLabel") {
            test("should be able to verify signatures") {
              checkAll(exhaustive(testVectors)) { testVector ->
                val signWithLabel = testVector.signWithLabel

                either {
                  cipherSuite.verifyWithLabel(
                    signWithLabel.pub,
                    signWithLabel.label,
                    signWithLabel.content,
                    signWithLabel.signature,
                  )
                }.shouldBeRight()
              }
            }

            test("should produce verifiable signatures") {
              checkAll(exhaustive(testVectors)) { testVector ->
                val signWithLabel = testVector.signWithLabel

                either {
                  cipherSuite.verifyWithLabel(
                    signWithLabel.pub,
                    signWithLabel.label,
                    signWithLabel.content,
                    cipherSuite.signWithLabel(signWithLabel.priv, signWithLabel.label, signWithLabel.content),
                  )
                }.shouldBeRight()
              }
            }
          }

          context("EncryptWithLabel") {
            test("should be able to decrypt ciphertexts") {
              checkAll(exhaustive(testVectors)) { testVector ->
                val encryptWithLabel = testVector.encryptWithLabel
                cipherSuite.decryptWithLabel(
                  encryptWithLabel.keyPair,
                  encryptWithLabel.label,
                  encryptWithLabel.context,
                  encryptWithLabel.hpkeCiphertext,
                ) shouldBe encryptWithLabel.plaintext
              }
            }

            test("should produce decryptable ciphertexts") {
              checkAll(exhaustive(testVectors)) { testVector ->
                val encryptWithLabel = testVector.encryptWithLabel

                cipherSuite.decryptWithLabel(
                  encryptWithLabel.keyPair,
                  encryptWithLabel.label,
                  encryptWithLabel.context,
                  cipherSuite.encryptWithLabel(
                    encryptWithLabel.pub,
                    encryptWithLabel.label,
                    encryptWithLabel.context,
                    encryptWithLabel.plaintext,
                  ),
                ) shouldBe encryptWithLabel.plaintext
              }
            }
          }
        }
      }
  }
}

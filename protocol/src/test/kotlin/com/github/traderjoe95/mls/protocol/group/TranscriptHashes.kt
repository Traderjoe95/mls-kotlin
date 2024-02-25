package com.github.traderjoe95.mls.protocol.group

import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.group.TranscriptHashesTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.util.hex
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class TranscriptHashes : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { TranscriptHashesTestVector.load(vertx) } +
      CipherSuite.validEntries.map(TranscriptHashesTestVector::generate)

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    @Suppress("UNCHECKED_CAST")
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<TranscriptHashesTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            test("should be able to verify a correct confirmation tag with a confirmation key of ${v.confirmationKey.hex}") {
              either {
                cipherSuite.verifyMac(
                  v.confirmationKey,
                  v.confirmedTranscriptHashAfter,
                  v.authenticatedContent.also {
                    it.contentType shouldBe ContentType.Commit
                    it.content.content.shouldBeInstanceOf<Commit>()
                  }.confirmationTag.shouldNotBeNull(),
                )
              }.shouldBeRight()
            }

            test(
              "should generate a correct confirmed transcript hash from the interim transcript hash ${v.interimTranscriptHashBefore.hex}",
            ) {
              updateConfirmedTranscriptHash(
                cipherSuite,
                v.interimTranscriptHashBefore,
                v.authenticatedContent.wireFormat,
                v.authenticatedContent.content as FramedContent<Commit>,
                v.authenticatedContent.signature,
              ) shouldBe v.confirmedTranscriptHashAfter
            }

            test(
              "should generate a correct interim transcript hash from the confirmation tag ${v.authenticatedContent.confirmationTag!!.hex}",
            ) {
              updateInterimTranscriptHash(
                cipherSuite,
                v.confirmedTranscriptHashAfter,
                v.authenticatedContent.confirmationTag!!,
              ) shouldBe v.interimTranscriptHashAfter
            }
          }
        }
      }
  }
}

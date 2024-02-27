package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupContext.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.interop.crypto.KeyScheduleTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.testing.shouldBeEq
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.util.hex
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.shouldBe

class KeyScheduleTestVectors : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { KeyScheduleTestVector.load(vertx) } +
      CipherSuite.validEntries.map { KeyScheduleTestVector.generate(it, 10U) }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<KeyScheduleTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            context("When seeding the key schedule for group ${v.groupId.hex} with ${v.initialInitSecret.hex}") {
              val initialKeySchedule = KeySchedule.uninitialized(cipherSuite, v.initialInitSecret)

              v.epochs
                .asSequence()
                .runningFoldIndexed(
                  Triple(
                    initialKeySchedule,
                    Secret.zeroes(cipherSuite.hashLen),
                    Secret.zeroes(cipherSuite.hashLen),
                  ),
                ) { epoch, (keySchedule, _, _), epochV ->
                  keySchedule.nextEpoch(
                    epochV.commitSecret,
                    epochV.groupContext(cipherSuite, v.groupId, epoch),
                    epochV.pskSecret,
                  )
                }
                .drop(1)
                .map { Triple(it.first as KeySchedule, it.second, it.third) }
                .forEachIndexed { epoch, (keySchedule, joinerSecret, welcomeSecret) ->
                  val epochV = v.epochs[epoch]

                  context("In epoch $epoch") {
                    test("the GroupContext should be as expected") {
                      epochV.groupContext(cipherSuite, v.groupId, epoch).encodeUnsafe() shouldBe epochV.groupContext
                    }

                    test("The joiner secret should be as expected") {
                      joinerSecret shouldBeEq epochV.joinerSecret
                    }

                    test("The welcome secret should be as expected") {
                      welcomeSecret shouldBeEq epochV.welcomeSecret
                    }

                    test("The init secret should be as expected") {
                      keySchedule.initSecret shouldBeEq epochV.initSecret
                    }

                    test("The sender data secret should be as expected") {
                      keySchedule.senderDataSecret shouldBeEq epochV.senderDataSecret
                    }

                    test("The encryption secret should be as expected") {
                      keySchedule.encryptionSecret shouldBeEq epochV.encryptionSecret
                    }

                    test("The exporter secret should be as expected") {
                      keySchedule.exporterSecret shouldBeEq epochV.exporterSecret
                    }

                    test("The epoch authenticator should be as expected") {
                      keySchedule.epochAuthenticator shouldBeEq epochV.epochAuthenticator
                    }

                    test("The external secret should be as expected") {
                      keySchedule.externalSecret shouldBeEq epochV.externalSecret
                    }

                    test("The confirmation key should be as expected") {
                      keySchedule.confirmationKey shouldBeEq epochV.confirmationKey
                    }

                    test("The membership key should be as expected") {
                      keySchedule.membershipKey shouldBeEq epochV.membershipKey
                    }

                    test("The resumption PSK should be as expected") {
                      keySchedule.resumptionPsk shouldBeEq epochV.resumptionPsk
                    }

                    test("The derived external public key should be as expected") {
                      keySchedule.externalKeyPair.public shouldBeEq epochV.externalPub
                    }

                    val exporter = epochV.exporter
                    test("The MLS Exporter secret for label ${exporter.label} and context ${exporter.context.hex} should be correct") {
                      keySchedule.mlsExporter(
                        exporter.label,
                        exporter.context,
                        exporter.length,
                      ) shouldBeEq exporter.secret
                    }
                  }
                }
            }
          }
        }
      }

    private fun KeyScheduleTestVector.Epoch.groupContext(
      cipherSuite: CipherSuite,
      groupId: GroupId,
      idx: Int,
    ): GroupContext =
      GroupContext(
        ProtocolVersion.MLS_1_0,
        cipherSuite,
        groupId,
        idx.toULong(),
        treeHash,
        confirmedTranscriptHash,
      )
  }
}

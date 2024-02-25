package com.github.traderjoe95.mls.protocol.message

import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.PublicMessageError
import com.github.traderjoe95.mls.protocol.error.PublicMessageSenderError
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.testing.shouldBeEq
import com.github.traderjoe95.mls.protocol.testing.shouldRaise
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.tree.SecretTree
import com.github.traderjoe95.mls.protocol.tree.SignaturePublicKeyLookup
import com.github.traderjoe95.mls.protocol.types.crypto.Mac.Companion.asMac
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class MessageProtection : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { MessageProtectionTestVector.load(vertx) } +
      CipherSuite.validEntries.map { runBlocking { MessageProtectionTestVector.generate(it) } }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<MessageProtectionTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            val groupContext = v.groupContext

            context("with group context ${groupContext.toShortString()}") {
              test("should be able to unprotect a public message containing a Proposal") {
                either {
                  v.proposalPub.message.unprotect(groupContext, v.membershipKey, v.signaturePub)
                }.shouldBeRight().content.content.shouldBeInstanceOf<Proposal>() shouldBeEqual v.proposal
              }

              test("should be able to protect a public message containing a Proposal, which can be unprotected again") {
                val pub =
                  unsafe {
                    val content = FramedContent.createMember(groupContext, v.proposal, LeafIndex(1U))
                    val authData =
                      FramedContent.AuthData(
                        content.sign(cipherSuite, WireFormat.MlsPublicMessage, groupContext, v.signaturePriv),
                        null,
                      )

                    MlsMessage.public(
                      groupContext,
                      content,
                      authData,
                      v.membershipKey,
                    )
                  }

                either {
                  pub.message.unprotect(groupContext, v.membershipKey, v.signaturePub)
                }.shouldBeRight().content.content.shouldBeInstanceOf<Proposal>() shouldBeEqual v.proposal
              }

              test("should be able to unprotect a public message containing a Commit") {
                either {
                  v.commitPub.message.unprotect(groupContext, v.membershipKey, v.signaturePub)
                }.shouldBeRight().content.content.shouldBeInstanceOf<Commit>() shouldBeEqual v.commit
              }

              test("should be able to protect a public message containing a Commit, which can be unprotected again") {
                val pub =
                  unsafe {
                    val content = FramedContent.createMember(groupContext, v.commit, LeafIndex(1U))
                    val authData =
                      FramedContent.AuthData(
                        content.sign(cipherSuite, WireFormat.MlsPublicMessage, groupContext, v.signaturePriv),
                        cipherSuite.generateSecret(cipherSuite.hashLen).bytes.asMac,
                      )

                    MlsMessage.public(
                      groupContext,
                      content,
                      authData,
                      v.membershipKey,
                    )
                  }

                either {
                  pub.message.unprotect(groupContext, v.membershipKey, v.signaturePub)
                }.shouldBeRight().content.content.shouldBeInstanceOf<Commit>() shouldBeEqual v.commit
              }

              test("should be able to unprotect a private message containing a Proposal") {
                val secretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                either {
                  v.proposalPriv.message.unprotect(
                    groupContext,
                    v.senderDataSecret,
                    secretTree,
                    SignaturePublicKeyLookup.only(v.signaturePub),
                  )
                }.shouldBeRight().content.content.shouldBeInstanceOf<Proposal>() shouldBeEqual v.proposal
              }

              test("should be able to protect a private message containing a Proposal, which can be unprotected again") {
                val senderSecretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                val priv =
                  unsafe {
                    val content = FramedContent.createMember(groupContext, v.proposal, LeafIndex(1U))
                    val authData =
                      FramedContent.AuthData(
                        content.sign(cipherSuite, WireFormat.MlsPrivateMessage, groupContext, v.signaturePriv),
                        null,
                      )

                    MlsMessage.private(
                      v.cipherSuite,
                      content,
                      authData,
                      senderSecretTree,
                      v.senderDataSecret,
                    )
                  }

                val recipientSecretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                either {
                  priv.message.unprotect(
                    groupContext,
                    v.senderDataSecret,
                    recipientSecretTree,
                    SignaturePublicKeyLookup.only(v.signaturePub),
                  )
                }.shouldBeRight().content.content.shouldBeInstanceOf<Proposal>() shouldBeEqual v.proposal
              }

              test("should be able to unprotect a private message containing a Commit") {
                val secretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                either {
                  v.commitPriv.message.unprotect(
                    groupContext,
                    v.senderDataSecret,
                    secretTree,
                    SignaturePublicKeyLookup.only(v.signaturePub),
                  )
                }.shouldBeRight().content.content.shouldBeInstanceOf<Commit>() shouldBeEqual v.commit
              }

              test("should be able to protect a private message containing a Commit, which can be unprotected again") {
                val senderSecretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                val priv =
                  unsafe {
                    val content = FramedContent.createMember(groupContext, v.commit, LeafIndex(1U))
                    val authData =
                      FramedContent.AuthData(
                        content.sign(cipherSuite, WireFormat.MlsPrivateMessage, groupContext, v.signaturePriv),
                        cipherSuite.generateSecret(cipherSuite.hashLen).bytes.asMac,
                      )

                    MlsMessage.private(
                      v.cipherSuite,
                      content,
                      authData,
                      senderSecretTree,
                      v.senderDataSecret,
                    )
                  }

                val recipientSecretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                either {
                  priv.message.unprotect(
                    groupContext,
                    v.senderDataSecret,
                    recipientSecretTree,
                    SignaturePublicKeyLookup.only(v.signaturePub),
                  )
                }.shouldBeRight().content.content.shouldBeInstanceOf<Commit>() shouldBeEqual v.commit
              }

              test("should be able to unprotect a private message containing application data") {
                val secretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                either {
                  v.applicationPriv.message.unprotect(
                    groupContext,
                    v.senderDataSecret,
                    secretTree,
                    SignaturePublicKeyLookup.only(v.signaturePub),
                  )
                }.shouldBeRight().content.content.shouldBeInstanceOf<ApplicationData>() shouldBeEq v.application
              }

              test("should be able to protect a private message containing application data, which can be unprotected again") {
                val senderSecretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                val priv =
                  unsafe {
                    val content = FramedContent.createMember(groupContext, v.application, LeafIndex(1U))
                    val authData =
                      FramedContent.AuthData(
                        content.sign(cipherSuite, WireFormat.MlsPrivateMessage, groupContext, v.signaturePriv),
                        null,
                      )

                    MlsMessage.private(
                      v.cipherSuite,
                      content,
                      authData,
                      senderSecretTree,
                      v.senderDataSecret,
                    )
                  }

                val recipientSecretTree = SecretTree.create(v.cipherSuite, v.encryptionSecret.copy(), 2U)

                either {
                  priv.message.unprotect(
                    groupContext,
                    v.senderDataSecret,
                    recipientSecretTree,
                    SignaturePublicKeyLookup.only(v.signaturePub),
                  )
                }.shouldBeRight().content.content.shouldBeInstanceOf<ApplicationData>() shouldBeEq v.application
              }

              test("should raise an error when trying to protect a public message containing application data") {
                shouldRaise<PublicMessageSenderError> {
                  val content = FramedContent.createMember(groupContext, v.application, LeafIndex(1U))
                  val authData =
                    FramedContent.AuthData(
                      content.sign(cipherSuite, WireFormat.MlsPublicMessage, groupContext, v.signaturePriv),
                      null,
                    )

                  MlsMessage.public(
                    groupContext,
                    content,
                    authData,
                    v.membershipKey,
                  )
                } shouldBe PublicMessageError.ApplicationMessageMustNotBePublic
              }
            }
          }
        }
      }
  }
}

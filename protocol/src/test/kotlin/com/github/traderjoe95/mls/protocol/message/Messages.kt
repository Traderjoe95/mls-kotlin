package com.github.traderjoe95.mls.protocol.message

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.protocol.interop.message.MessagesTestVector
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.coerceFormat
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.ExternalInit
import com.github.traderjoe95.mls.protocol.types.framing.content.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.kotest.common.runBlocking
import io.kotest.core.spec.style.scopes.FunSpecContainerScope
import io.kotest.matchers.shouldBe
import kotlin.reflect.KProperty0

class Messages : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { MessagesTestVector.load(vertx) } + (1..20).map { runBlocking { MessagesTestVector.generate() } }

  testVectors.forEachIndexed { idx, testVector ->
    context("For test vector ${idx + 1}") {
      testVector.shouldDecodeAndEncode(
        "Welcome Messages",
        MlsMessage,
        testVector::mlsWelcome,
      ) { it.coerceFormat<Welcome>() }

      testVector.shouldDecodeAndEncode(
        "Group Info Messages",
        MlsMessage,
        testVector::mlsGroupInfo,
      ) { it.coerceFormat<GroupInfo>() }

      testVector.shouldDecodeAndEncode(
        "Key Package Messages",
        MlsMessage,
        testVector::mlsKeyPackage,
      ) { it.coerceFormat<KeyPackage>() }

      testVector.shouldDecodeAndEncode("Ratchet Trees", PublicRatchetTree, testVector::ratchetTree)
      testVector.shouldDecodeAndEncode("GroupSecrets", GroupSecrets, testVector::groupSecrets)

      testVector.shouldDecodeAndEncode("Add Proposals", Add.T, testVector::addProposal)
      testVector.shouldDecodeAndEncode("Update Proposals", Update.T, testVector::updateProposal)
      testVector.shouldDecodeAndEncode("Remove Proposals", Remove.T, testVector::removeProposal)
      testVector.shouldDecodeAndEncode("Pre-Shared Key Proposals", PreSharedKey.T, testVector::preSharedKeyProposal)
      testVector.shouldDecodeAndEncode("Re-Init Proposals", ReInit.T, testVector::reInitProposal)
      testVector.shouldDecodeAndEncode("External Init Proposals", ExternalInit.T, testVector::externalInitProposal)
      testVector.shouldDecodeAndEncode(
        "Group Context Ext Proposals",
        GroupContextExtensions.T,
        testVector::groupContextExtensionsProposal,
      )

      testVector.shouldDecodeAndEncode("Commits", Commit, testVector::commit)
    }
  }
}) {
  @Suppress("DUPLICATED_TEST_NAME")
  companion object {
    context(FunSpecContainerScope)
    suspend fun <T> MessagesTestVector.shouldDecodeAndEncode(
      title: String,
      encodable: Encodable<T>,
      getBytes: KProperty0<ByteArray>,
      additionalValidation: (T) -> Any = {},
    ) {
      context(title) {
        test("should be decoded properly") {
          additionalValidation(encodable.decodeUnsafe(getBytes()))
        }

        test("should round-trip to the same binary value") {
          with(encodable) {
            decodeUnsafe(getBytes()).encodeUnsafe() shouldBe getBytes()
          }
        }
      }
    }

    context(FunSpecContainerScope)
    suspend fun <T> MessagesTestVector.shouldDecodeAndEncode(
      title: String,
      dataType: DataType<T>,
      getBytes: KProperty0<ByteArray>,
      additionalValidation: (T) -> Any = {},
    ) {
      context(title) {
        test("should be decoded properly") {
          additionalValidation(unsafe { getBytes().decodeAs(dataType) })
        }

        test("should round-trip to the same binary value") {
          with(dataType) {
            unsafe { encode(getBytes().decodeAs(dataType)) } shouldBe getBytes()
          }
        }
      }
    }
  }
}

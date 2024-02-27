package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.tree.TreeOperationsTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.content.Update
import com.github.traderjoe95.mls.protocol.util.hex
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.shouldBe

class TreeOperations : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { TreeOperationsTestVector.load(vertx) } +
      CipherSuite.validEntries.flatMap { cs ->
        TreeOperationsTestVector.Scenario.entries.map { cs to it }
      }.map { (cs, sc) -> TreeOperationsTestVector.generate(cs, sc) }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<TreeOperationsTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            context("with an initial tree having tree hash ${v.treeHashBefore.hex}") {
              test("should be able to decode the initial tree") {
                either { PublicRatchetTree.decode(v.treeBefore) }.shouldBeRight()
              }

              test("should produce the expected tree hash for the initial tree") {
                PublicRatchetTree.decodeUnsafe(v.treeBefore).treeHash(cipherSuite) shouldBe v.treeHashBefore
              }

              context("after applying an ${v.proposal.type} proposal sent by leaf ${v.proposalSender.value}") {
                val treeBefore = PublicRatchetTree.decodeUnsafe(v.treeBefore)

                val treeAfter =
                  when (val prop = v.proposal) {
                    is Add -> treeBefore.insert(prop.keyPackage.leafNode).first
                    is Update -> treeBefore.update(v.proposalSender, prop.leafNode)
                    is Remove -> treeBefore.remove(prop.removed)
                    else -> error("Unsupported proposal type ${prop.type}: $prop")
                  }

                test("the tree should be as expected") {
                  treeAfter.encodeUnsafe() shouldBe v.treeAfter
                }

                test("the tree hash should be as expected") {
                  treeAfter.treeHash(cipherSuite) shouldBe v.treeHashAfter
                }
              }
            }
          }
        }
      }
  }
}

package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.tree.TreeValidationTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.util.hex
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.shouldBe

class TreeValidation : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { TreeValidationTestVector.load(vertx) } +
      CipherSuite.validEntries.flatMap { cs ->
        TreeValidationTestVector.allStructures().map { cs to it }
      }.map { (cs, structure) -> TreeValidationTestVector.generate(cs, structure) }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<TreeValidationTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            context(
              "in the tree with ${v.tree.leaves.size} leaves, of which ${v.tree.nonBlankLeafIndices.size} " +
                "are none-blank [th=${v.tree.treeHash(cipherSuite).hex}]",
            ) {
              context("the resolution of") {
                v.tree.indices.forEach { node ->
                  test("node ${node.value} should be ${v.resolutions[node.value.toInt()]}") {
                    v.tree.resolution(node).map { it.value } shouldBe v.resolutions[node.value.toInt()]
                  }
                }
              }

              context("the tree hash of") {
                v.tree.indices.forEach { node ->
                  test("node ${node.value} should be ${v.treeHashes[node.value.toInt()].hex}") {
                    v.tree.treeHash(node, cipherSuite) shouldBe v.treeHashes[node.value.toInt()]
                  }
                }
              }

              test("the tree should be parent-hash-valid") {
                either { v.tree.checkParentHashCoverage(cipherSuite) }.shouldBeRight()
              }

              context("the signature of") {
                v.tree.nonBlankLeafIndices.forEach { leaf ->
                  test("leaf ${leaf.value} should be correct") {
                    either { v.tree.leafNode(leaf).verifySignature(cipherSuite, v.groupId, leaf) }.shouldBeRight()
                  }
                }
              }
            }
          }
        }
      }
  }
}

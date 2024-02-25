package com.github.traderjoe95.mls.protocol.tree

import com.github.traderjoe95.mls.protocol.interop.tree.TreeMathTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.shouldBe

class TreeMath : VertxFunSpec({ vertx ->
  val testVectors = runBlocking { TreeMathTestVector.load(vertx) }

  testVectors.forEach {
    include(testVectorTests(it, selfGenerated = false))
  }

  listOf(1U, 2U, 4U, 8U, 16U, 32U, 64U, 128U, 256U).map { TreeMathTestVector.generate(it) }.forEach {
    include(testVectorTests(it, selfGenerated = true))
  }
}) {
  companion object {
    fun testVectorTests(
      testVector: TreeMathTestVector,
      selfGenerated: Boolean,
    ): TestFactory =
      funSpec {
        val tree = PublicRatchetTree.blankWithLeaves(testVector.nLeaves)

        context("In a tree with ${testVector.nLeaves} leaves [generated=$selfGenerated]") {
          test("there should be ${testVector.nNodes} nodes") {
            tree.size shouldBe testVector.nNodes
          }

          test("the root should have index ${testVector.root}") {
            tree.root.value shouldBe testVector.root
          }

          context("the left child") {
            testVector.left.forEachIndexed { index, leftChild ->
              if (leftChild != null) {
                test("of node $index should be $leftChild") {
                  NodeIndex(index.toUInt()).leftChild.value shouldBe leftChild
                }
              }
            }
          }

          context("the right child") {
            testVector.right.forEachIndexed { index, rightChild ->
              if (rightChild != null) {
                test("of node $index should be $rightChild") {
                  NodeIndex(index.toUInt()).rightChild.value shouldBe rightChild
                }
              }
            }
          }

          context("the parent") {
            testVector.parent.forEachIndexed { index, parent ->
              if (parent != null) {
                test("of node $index should be $parent") {
                  NodeIndex(index.toUInt()).parent.value shouldBe parent
                }
              }
            }
          }

          context("the sibling") {
            testVector.sibling.forEachIndexed { index, sibling ->
              if (sibling != null) {
                test("of node $index should be $sibling") {
                  NodeIndex(index.toUInt()).sibling.value shouldBe sibling
                }
              }
            }
          }
        }
      }
  }
}

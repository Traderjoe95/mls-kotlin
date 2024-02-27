package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.either
import arrow.core.raise.nullable
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.interop.tree.TreeKemTestVector
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.testing.shouldBeEq
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.util.hex
import com.github.traderjoe95.mls.protocol.util.unsafe
import com.github.traderjoe95.mls.protocol.util.zipWithIndex
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.common.runBlocking
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.shouldBe
import java.util.concurrent.ConcurrentHashMap

class TreeKem : VertxFunSpec({ vertx ->
  val testVectors =
    runBlocking { TreeKemTestVector.load(vertx) } +
      CipherSuite.validEntries.flatMap { cs ->
        TreeKemTestVector.allStructures().map { cs to it }
      }.map { (cs, structure) -> TreeKemTestVector.generate(cs, structure) }

  testVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
    include(testVectorTests(cipherSuite, testVectors))
  }
}) {
  companion object {
    fun testVectorTests(
      cipherSuite: CipherSuite,
      testVectors: List<TreeKemTestVector>,
    ): TestFactory =
      funSpec {
        context("Cipher Suite $cipherSuite") {
          testVectors.forEach { v ->
            context(
              "in the tree with ${v.ratchetTree.leaves.size} leaves, " +
                "of which ${v.ratchetTree.nonBlankLeafIndices.size} are none-blank " +
                "[th=${v.ratchetTree.treeHash(cipherSuite).hex}]",
            ) {
              val leavesPrivate =
                List(v.ratchetTree.leaves.size) { leafIdx ->
                  v.leavesPrivate
                    .find { it.index.value.toInt() == leafIdx }
                    ?.let { leafPriv ->
                      PrivateRatchetTree(
                        cipherSuite,
                        leafPriv.index,
                        leafPriv.pathSecrets.associate { it.node to it.pathSecret },
                        mapOf(leafPriv.index.nodeIndex to leafPriv.encryptionPriv).toMap(ConcurrentHashMap()),
                      ) to leafPriv.signaturePriv
                    }
                }

              context("the private state of") {
                leavesPrivate.indices
                  .mapNotNull {
                    nullable {
                      LeafIndex(it.toUInt()) to RatchetTree(cipherSuite, v.ratchetTree, leavesPrivate[it].bind().first)
                    }
                  }
                  .forEach { (leaf, tree) ->
                    test("non-blank leaf ${leaf.value} should be consistent with the public state") {
                      (tree.private.pathSecrets.keys + tree.private.privateKeyCache.keys).forEach { cachedNode ->
                        with(tree) { cachedNode.isBlank }.shouldBeFalse()

                        cipherSuite.reconstructPublicKey(
                          tree.getPrivateKey(cachedNode)!!,
                        ).public shouldBeEq tree.node(cachedNode).encryptionKey
                      }
                    }
                  }
              }

              v.updatePaths.forEach { up ->
                val senderTree = RatchetTree(cipherSuite, v.ratchetTree, leavesPrivate[up.sender.value.toInt()]!!.first)
                val senderSig = leavesPrivate[up.sender.value.toInt()]!!.second

                val updatedSenderTree = unsafe { senderTree.mergeUpdatePath(up.sender, up.updatePath) }
                val groupContext =
                  GroupContext(
                    ProtocolVersion.MLS_1_0,
                    v.cipherSuite,
                    v.groupId,
                    v.epoch,
                    updatedSenderTree.treeHash,
                    v.confirmedTranscriptHash,
                  )

                val (_, newUpdatePath, pathSecrets) =
                  unsafe {
                    createUpdatePath(updatedSenderTree, setOf(), groupContext, senderSig)
                  }
                val newCommitSecret = cipherSuite.deriveSecret(pathSecrets.last(), "path")

                context("for the update path sent by ${up.sender.value} [commitSecret=${up.commitSecret.hex}]") {
                  up.pathSecrets
                    .zipWithIndex()
                    .mapNotNull { nullable { it.first.bind() to it.second } }
                    .forEach { (expectedPathSecret, idx) ->
                      val leafTree = RatchetTree(cipherSuite, v.ratchetTree, leavesPrivate[idx]!!.first)

                      context("for non-blank leaf $idx") {
                        test("the update path should be parent-hash valid") {
                          either { leafTree.mergeUpdatePath(up.sender, up.updatePath) }.shouldBeRight()
                        }

                        test("the tree hash after merging the update path should be ${up.treeHashAfter.hex}") {
                          unsafe {
                            leafTree.mergeUpdatePath(up.sender, up.updatePath)
                          }.treeHash shouldBe up.treeHashAfter
                        }

                        test("the decrypted path secret should be ${expectedPathSecret.hex}") {
                          val updatedTree = unsafe { leafTree.mergeUpdatePath(up.sender, up.updatePath) }

                          updatedTree.extractCommonPathSecret(
                            up.sender,
                            up.updatePath,
                            groupContext,
                            setOf(),
                          ).second shouldBeEq expectedPathSecret
                        }

                        test("a new update path generated by the sender should be successfully processed") {
                          val updatedTree = unsafe { leafTree.mergeUpdatePath(up.sender, up.updatePath) }
                          unsafe {
                            applyUpdatePath(updatedTree, groupContext, up.sender, newUpdatePath, setOf())
                          }.second shouldBeEq newCommitSecret
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

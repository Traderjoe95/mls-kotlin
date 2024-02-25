package com.github.traderjoe95.mls.protocol.interop.tree

import com.github.traderjoe95.mls.protocol.tree.NodeIndex
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait

data class TreeMathTestVector(
  val nLeaves: UInt,
  val nNodes: UInt,
  val root: UInt,
  val left: List<UInt?>,
  val right: List<UInt?>,
  val parent: List<UInt?>,
  val sibling: List<UInt?>,
) {
  constructor(json: JsonObject) : this(
    json.getLong("n_leaves").toUInt(),
    json.getLong("n_nodes").toUInt(),
    json.getLong("root").toUInt(),
    json.getJsonArray("left").filterIsInstance<Number?>().map { it?.toLong()?.toUInt() },
    json.getJsonArray("right").filterIsInstance<Number?>().map { it?.toLong()?.toUInt() },
    json.getJsonArray("parent").filterIsInstance<Number?>().map { it?.toLong()?.toUInt() },
    json.getJsonArray("sibling").filterIsInstance<Number?>().map { it?.toLong()?.toUInt() },
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/tree-math.json",
    ): List<TreeMathTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { TreeMathTestVector(it as JsonObject) }

    fun generate(leafCount: UInt): TreeMathTestVector {
      val nodeCount = 2U * leafCount - 1U

      return TreeMathTestVector(
        leafCount,
        nodeCount,
        NodeIndex.root(nodeCount).value,
        (NodeIndex(0U)..<NodeIndex(nodeCount)).map { it.leftChild.value },
        (NodeIndex(0U)..<NodeIndex(nodeCount)).map { it.rightChild.value },
        (NodeIndex(0U)..<NodeIndex(nodeCount)).map { it.parent.value },
        (NodeIndex(0U)..<NodeIndex(nodeCount)).map { it.sibling.value },
      )
    }
  }
}

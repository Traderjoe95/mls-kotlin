package com.github.traderjoe95.mls.protocol.interop.tree

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getUInt
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait

data class TreeOperationsTestVector(
  val cipherSuite: CipherSuite,
  val treeBefore: ByteArray,
  val proposal: Proposal,
  val proposalSender: LeafIndex,
  val treeHashBefore: ByteArray,
  val treeAfter: ByteArray,
  val treeHashAfter: ByteArray,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getHexBinary("tree_before"),
    Proposal.decodeUnsafe(json.getHexBinary("proposal")),
    LeafIndex(json.getUInt("proposal_sender")),
    json.getHexBinary("tree_hash_before"),
    json.getHexBinary("tree_after"),
    json.getHexBinary("tree_hash_after"),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/tree-operations.json",
    ): List<TreeOperationsTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { TreeOperationsTestVector(it as JsonObject) }
  }
}

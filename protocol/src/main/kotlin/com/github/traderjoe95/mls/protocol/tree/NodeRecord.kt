package com.github.traderjoe95.mls.protocol.tree

import com.github.traderjoe95.mls.codec.util.mapFirst
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode

sealed interface NodeRecord<N : Node> {
  val pair: Pair<N, HpkePrivateKey?>

  val node: N
    get() = pair.first

  val publicKey: HpkePublicKey
    get() = node.encryptionKey
  val privateKey: HpkePrivateKey?
    get() = pair.second
  val keyPair: HpkeKeyPair?
    get() = privateKey?.let { HpkeKeyPair(it to publicKey) }

  val hasPrivateKey: Boolean
    get() = privateKey != null

  val asLeaf: LeafNodeRecord
    get() = this as LeafNodeRecord

  val asParent: ParentNodeRecord
    get() = this as ParentNodeRecord

  fun updateNode(update: N.() -> N): NodeRecord<N>

  fun withPrivateKey(privateKey: HpkePrivateKey?): NodeRecord<N>
}

@JvmInline
value class ParentNodeRecord(override val pair: Pair<ParentNode, HpkePrivateKey?>) : NodeRecord<ParentNode> {
  override fun updateNode(update: ParentNode.() -> ParentNode): ParentNodeRecord = ParentNodeRecord(pair.mapFirst(update))

  override fun withPrivateKey(privateKey: HpkePrivateKey?): ParentNodeRecord = ParentNodeRecord(pair.first to privateKey)

  companion object {
    fun new(keyPair: HpkeKeyPair): ParentNodeRecord = ParentNodeRecord(ParentNode.new(keyPair.public) to keyPair.private)

    fun new(
      publicKey: HpkePublicKey,
      privateKey: HpkePrivateKey?,
    ): ParentNodeRecord = ParentNodeRecord(ParentNode.new(publicKey) to privateKey)
  }
}

@JvmInline
value class LeafNodeRecord(override val pair: Pair<LeafNode<*>, HpkePrivateKey?>) : NodeRecord<LeafNode<*>> {
  override fun updateNode(update: LeafNode<*>.() -> LeafNode<*>): LeafNodeRecord = LeafNodeRecord(pair.mapFirst(update))

  override fun withPrivateKey(privateKey: HpkePrivateKey?): LeafNodeRecord = LeafNodeRecord(pair.first to privateKey)
}

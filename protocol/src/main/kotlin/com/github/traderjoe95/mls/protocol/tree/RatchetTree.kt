package com.github.traderjoe95.mls.protocol.tree

import arrow.core.Option
import arrow.core.prependTo
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree.Companion.newTree
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.types.tree.UpdateLeafNode
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.protocol.util.log2
import com.github.traderjoe95.mls.protocol.util.shl
import com.github.traderjoe95.mls.protocol.util.sliceArray
import com.github.traderjoe95.mls.protocol.util.uSize

sealed interface RatchetTreeOps {
  val size: UInt

  val root: NodeIndex

  val leafNodeIndices: NodeProgression
  val parentNodeIndices: NodeProgression

  val leaves: List<LeafNode<*>?>

  val firstBlankLeaf: LeafIndex?

  val TreeIndex.filteredParent: NodeIndex

  val TreeIndex.isBlank: Boolean

  operator fun get(nodeIndex: TreeIndex): Node?

  operator fun get(nodeIndices: Iterable<TreeIndex>): List<Node?>

  fun directPath(node: TreeIndex): List<NodeIndex>

  fun coPath(node: TreeIndex): List<NodeIndex>

  fun filteredDirectPath(node: TreeIndex): List<NodeIndex>

  fun resolution(node: TreeIndex): List<NodeIndex>

  fun node(idx: TreeIndex): Node

  fun parentNode(idx: NodeIndex): ParentNode

  fun leafNode(idx: TreeIndex): LeafNode<*>

  fun leafNodeOrNull(idx: TreeIndex): LeafNode<*>?
}

class RatchetTree(
  val cipherSuite: CipherSuite,
  internal val public: PublicRatchetTree,
  internal val private: PrivateRatchetTree,
) : RatchetTreeOps by public {
  val leafIndex: LeafIndex
    get() = private.leafIndex

  fun insert(newLeaf: LeafNode<*>): Pair<RatchetTree, LeafIndex> =
    public.insert(newLeaf).let { (newPublic, newLeaf) ->
      RatchetTree(cipherSuite, newPublic, private) to newLeaf
    }

  fun update(
    leafIndex: LeafIndex,
    leafNode: UpdateLeafNode,
  ): RatchetTree = set(leafIndex, leafNode).blank(directPath(leafIndex).dropLast(1))

  fun remove(leafIndex: LeafIndex): RatchetTree =
    (public - leafIndex).let { newPublic ->
      RatchetTree(
        cipherSuite,
        newPublic,
        private.truncateToSize(newPublic.size),
      )
    }

  fun blank(indices: Iterable<TreeIndex>): RatchetTree = RatchetTree(cipherSuite, public.blank(indices), private.blank(indices))

  fun set(
    nodeIndex: TreeIndex,
    node: Node?,
  ): RatchetTree =
    RatchetTree(
      cipherSuite,
      public.set(nodeIndex, node),
      if (public[nodeIndex]?.encryptionKey != node?.encryptionKey) {
        private.blank(nodeIndex)
      } else {
        private
      },
    )

  fun set(
    nodeIndex: TreeIndex,
    node: Node,
    privateKey: HpkePrivateKey,
  ): RatchetTree =
    RatchetTree(
      cipherSuite,
      public.set(nodeIndex, node),
      private.add(nodeIndex, privateKey),
    )

  fun set(
    nodeIndex: TreeIndex,
    privateKey: HpkePrivateKey,
  ): RatchetTree =
    RatchetTree(
      cipherSuite,
      public,
      private.add(nodeIndex, privateKey),
    )

  inline fun update(
    nodeIndex: TreeIndex,
    update: Node?.() -> Node?,
  ): RatchetTree = set(nodeIndex, this[nodeIndex].update())

  inline fun updateOrNull(
    nodeIndex: TreeIndex,
    update: Node.() -> Node?,
  ): RatchetTree = update(nodeIndex) { this?.update() }

  fun getPrivateKey(nodeIndex: TreeIndex): HpkePrivateKey? = private.privateKeys[nodeIndex.nodeIndex]

  fun getKeyPair(nodeIndex: TreeIndex): HpkeKeyPair? = getPrivateKey(nodeIndex)?.let { HpkeKeyPair(it to node(nodeIndex).encryptionKey) }

  internal fun removeLeaves(leaves: Set<LeafIndex>): RatchetTree =
    if (leaves.isEmpty()) {
      this
    } else {
      RatchetTree(
        cipherSuite,
        public.removeLeaves(leaves),
        private.blank(leaves),
      )
    }

  companion object {
    fun new(
      cipherSuite: CipherSuite,
      leafNode: KeyPackageLeafNode,
      decryptionKey: HpkePrivateKey,
    ): RatchetTree =
      RatchetTree(
        cipherSuite,
        leafNode.newTree(),
        PrivateRatchetTree(LeafIndex(0U), mapOf(NodeIndex(0U) to decryptionKey)),
      )

    fun PublicRatchetTree.insert(
      cipherSuite: CipherSuite,
      ownLeafNode: KeyPackageLeafNode,
      decryptionKey: HpkePrivateKey,
    ): RatchetTree =
      insert(ownLeafNode).let { (newPublic, newLeaf) ->
        RatchetTree(
          cipherSuite,
          newPublic,
          PrivateRatchetTree(newLeaf, mapOf(newLeaf.nodeIndex to decryptionKey)),
        )
      }

    fun PublicRatchetTree.join(
      cipherSuite: CipherSuite,
      leafIndex: LeafIndex,
      decryptionKey: HpkePrivateKey,
    ): RatchetTree =
      RatchetTree(
        cipherSuite,
        this,
        PrivateRatchetTree(leafIndex, mapOf(leafIndex.nodeIndex to decryptionKey)),
      )
  }
}

@JvmInline
value class PublicRatchetTree private constructor(private val nodes: Array<Node?>) : RatchetTreeOps {
  override val size: UInt
    get() = nodes.uSize
  override val root: NodeIndex
    get() = NodeIndex((1U shl log2(size)) - 1U)

  override val leafNodeIndices: NodeProgression
    get() = NodeIndex(0U)..<size step 2
  override val parentNodeIndices: NodeProgression
    get() = NodeIndex(1U)..<size step 2

  @Suppress("UNCHECKED_CAST", "kotlin:S6531")
  override val leaves: List<LeafNode<*>?>
    get() = this[leafNodeIndices] as List<LeafNode<*>?>

  override val firstBlankLeaf: LeafIndex?
    get() = leafNodeIndices.find { it.isBlank }?.leafIndex

  fun insert(newLeaf: LeafNode<*>): Pair<PublicRatchetTree, LeafIndex> =
    firstBlankLeaf
      ?.let { newLeaf.insertAt(it.nodeIndex) }
      ?: extend().insert(newLeaf)

  private fun LeafNode<*>.insertAt(nodeIdx: NodeIndex): Pair<PublicRatchetTree, LeafIndex> {
    val leafIdx = nodeIdx.leafIndex
    val intermediateDirectPath = directPath(nodeIdx).dropLast(1).map { it.value.toInt() }.toSet()

    return PublicRatchetTree(
      Array(nodes.size) {
        if (it.toUInt() == nodeIdx.value) {
          this
        } else if (it in intermediateDirectPath) {
          nodes[it]?.asParent?.run { copy(unmergedLeaves = unmergedLeaves + leafIdx) }
        } else {
          nodes[it]
        }
      },
    ) to leafIdx
  }

  operator fun minus(leafIndex: LeafIndex): PublicRatchetTree {
    val intermediateDirectPath = directPath(leafIndex).dropLast(1).map { it.value.toInt() }.toSet()
    val nodeIdx = leafIndex.nodeIndex.value.toInt()

    return PublicRatchetTree(
      Array(nodes.size) {
        if (it == nodeIdx || it in intermediateDirectPath) {
          null
        } else {
          nodes[it]
        }
      },
    ).truncateIfRequired()
  }

  fun update(
    leafIndex: LeafIndex,
    leafNode: UpdateLeafNode,
  ): PublicRatchetTree =
    set(leafIndex, leafNode)
      .blank(directPath(leafIndex).dropLast(1))

  fun blank(indices: Iterable<TreeIndex>): PublicRatchetTree =
    indices.map { it.nodeIndex.value.toInt() }.toSet().let { blanked ->
      PublicRatchetTree(Array(nodes.size) { if (it in blanked) null else nodes[it] })
    }

  internal fun removeLeaves(leaves: Set<LeafIndex>): PublicRatchetTree {
    if (leaves.isEmpty()) return this

    val leafNodeIndices = leaves.map { it.nodeIndex.value.toInt() }.toSet()
    val removedLeafParentNodes = leaves.flatMap(::directPath).map { it.value.toInt() }.toSet()

    return PublicRatchetTree(
      Array(nodes.size) {
        if (it in leafNodeIndices) {
          null
        } else if (it in removedLeafParentNodes) {
          nodes[it]?.asParent?.run { copy(unmergedLeaves = unmergedLeaves - leaves) }
        } else {
          nodes[it]
        }
      },
    )
  }

  override val TreeIndex.filteredParent: NodeIndex
    get() = filteredDirectPath(this).firstOrNull() ?: root

  override val TreeIndex.isBlank: Boolean
    get() = nodeIndex >= nodes.size.toUInt() || nodes[nodeIndex.value] == null

  override operator fun get(nodeIndex: TreeIndex): Node? = nodes[nodeIndex.nodeIndex.value]

  override operator fun get(nodeIndices: Iterable<TreeIndex>): List<Node?> = nodes[nodeIndices.map { it.nodeIndex.value }]

  fun set(
    nodeIndex: TreeIndex,
    node: Node?,
  ): PublicRatchetTree =
    nodeIndex.nodeIndex.let { idx ->
      PublicRatchetTree(Array(nodes.size) { if (it.toUInt() == idx.value) node else nodes[it] })
    }

  private val leftSubtree: PublicRatchetTree
    get() = PublicRatchetTree(nodes.sliceArray(0U..<root.value))

  private fun extend(): PublicRatchetTree {
    return PublicRatchetTree(
      Array<Node?>(nodes.size * 2 + 1) { null }.also { nodes.copyInto(it, 0) },
    )
  }

  private fun truncateIfRequired(): PublicRatchetTree =
    generateSequence(leftSubtree) { it.leftSubtree }
      .dropWhile { ((it.root + 1U)..<it.size).all { node -> node.isBlank } }
      .first()

  override fun directPath(node: TreeIndex): List<NodeIndex> =
    node.nodeIndex.let { nodeIdx ->
      if (nodeIdx >= size || nodeIdx == root) {
        emptyList()
      } else {
        var current = nodeIdx
        val path = mutableListOf<NodeIndex>()

        while (current != root) {
          current = current.parent
          path.add(current)
        }

        path.toList()
      }
    }

  override fun coPath(node: TreeIndex): List<NodeIndex> =
    node.nodeIndex.let { nodeIdx ->
      nodeIdx.prependTo(directPath(nodeIdx))
        .dropLast(1)
        .map { it.sibling }
    }

  override fun filteredDirectPath(node: TreeIndex): List<NodeIndex> =
    node.nodeIndex.let { nodeIdx ->
      directPath(nodeIdx).zip(coPath(nodeIdx)).filterNot { (_, coPathChild) ->
        resolution(coPathChild).isEmpty()
      }.map { it.first }
    }

  override fun resolution(node: TreeIndex): List<NodeIndex> =
    node.nodeIndex.let { nodeIdx ->
      if (nodeIdx >= size) {
        emptyList()
      } else {
        val toResolve = mutableListOf(nodeIdx)
        val result = mutableListOf<NodeIndex>()

        while (toResolve.isNotEmpty()) {
          val current = toResolve.removeAt(0)

          when {
            current.isBlank && current.isParent ->
              toResolve.addAll(0, listOf(current.leftChild, current.rightChild))

            !current.isBlank && current.isLeaf ->
              result.add(current)

            !current.isBlank -> result.addAll(current.prependTo(parentNode(current).unmergedLeaves.map { it.nodeIndex }))
          }
        }

        result.toList()
      }
    }

  override fun node(idx: TreeIndex): Node = this[idx.nodeIndex]!!

  override fun parentNode(idx: NodeIndex): ParentNode = this[idx]!!.asParent

  override fun leafNode(idx: TreeIndex): LeafNode<*> = this[idx.nodeIndex]!!.asLeaf

  override fun leafNodeOrNull(idx: TreeIndex): LeafNode<*>? = this[idx.nodeIndex]?.asLeaf

  companion object : Encodable<PublicRatchetTree> {
    override val dataT: DataType<PublicRatchetTree> =
      optional[Node.dataT][V].derive(
        { nodes ->
          if (nodes.last().isNone()) {
            raise(DecoderError.UnexpectedError("Last node of an encoded ratchet tree must not be blank"))
          }

          val d = log2(nodes.uSize)
          val synthesizeBlankNodes = (1U shl (d + 1U)) - nodes.uSize - 1U

          PublicRatchetTree(
            nodes.map { it.getOrNull() }.toTypedArray() + Array<Node?>(synthesizeBlankNodes.toInt()) { null },
          )
        },
        { tree -> tree.nodes.map(Option.Companion::fromNullable).dropLastWhile(Option<Node>::isNone) },
      )

    fun LeafNode<*>.newTree(): PublicRatchetTree = PublicRatchetTree(arrayOf(this))

    fun blankWithLeaves(leafCount: UInt): PublicRatchetTree = PublicRatchetTree(Array(2 * leafCount.toInt() - 1) { null })
  }
}

data class PrivateRatchetTree(
  val leafIndex: LeafIndex,
  val privateKeys: Map<NodeIndex, HpkePrivateKey>,
) {
  fun add(
    nodeIndex: TreeIndex,
    privateKey: HpkePrivateKey,
  ): PrivateRatchetTree = PrivateRatchetTree(leafIndex, privateKeys + (nodeIndex.nodeIndex to privateKey))

  fun blank(indices: Iterable<TreeIndex>) = PrivateRatchetTree(leafIndex, privateKeys - indices.map { it.nodeIndex }.toSet())

  fun blank(idx: TreeIndex) = PrivateRatchetTree(leafIndex, privateKeys - idx.nodeIndex)

  fun truncateToSize(size: UInt): PrivateRatchetTree = PrivateRatchetTree(leafIndex, privateKeys.filterKeys { it < size })
}

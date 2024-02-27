package com.github.traderjoe95.mls.protocol.tree

import arrow.core.Option
import arrow.core.prependTo
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.optional
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.tree.PublicRatchetTree.Companion.newTree
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.Node
import com.github.traderjoe95.mls.protocol.types.tree.ParentNode
import com.github.traderjoe95.mls.protocol.util.get
import com.github.traderjoe95.mls.protocol.util.log2
import com.github.traderjoe95.mls.protocol.util.shl
import com.github.traderjoe95.mls.protocol.util.sliceArray
import com.github.traderjoe95.mls.protocol.util.uSize
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap

sealed interface RatchetTreeOps : SignaturePublicKeyLookup {
  val size: UInt

  val root: NodeIndex

  val indices: NodeRange
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

  context(Raise<SignatureError.SignaturePublicKeyKeyNotFound>)
  override fun getSignaturePublicKey(
    groupContext: GroupContext,
    framedContent: FramedContent<*>,
  ): SignaturePublicKey = findSignaturePublicKey(framedContent, groupContext, this)
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
    leafNode: LeafNode<*>,
  ): RatchetTree = set(leafIndex, leafNode).blank(directPath(leafIndex).dropLast(1))

  fun remove(leafIndex: LeafIndex): RatchetTree =
    (public.remove(leafIndex)).let { newPublic ->
      RatchetTree(
        cipherSuite,
        newPublic,
        private.truncateToSize(newPublic.size),
      )
    }

  fun remove(leafIndices: List<LeafIndex>): RatchetTree =
    (public.remove(leafIndices)).let { newPublic ->
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
    privateEncryptionKey: HpkePrivateKey,
  ): RatchetTree =
    RatchetTree(
      cipherSuite,
      public.set(nodeIndex, node),
      private.add(nodeIndex, privateEncryptionKey),
    )

  fun set(
    nodeIndex: TreeIndex,
    node: Node,
    pathSecret: Secret,
  ): RatchetTree =
    RatchetTree(
      cipherSuite,
      public.set(nodeIndex, node),
      private.add(nodeIndex, pathSecret),
    )

  fun insertPathSecrets(
    from: TreeIndex,
    pathSecret: Secret,
  ): RatchetTree =
    RatchetTree(
      cipherSuite,
      public,
      private.insertPathSecrets(public, from, pathSecret),
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

  fun getPrivateKey(nodeIndex: TreeIndex): HpkePrivateKey? = private.getPrivateKey(nodeIndex)

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
    fun new(keyPackage: KeyPackage.Private): RatchetTree =
      RatchetTree(
        keyPackage.cipherSuite,
        keyPackage.leafNode.newTree(),
        PrivateRatchetTree(
          keyPackage.cipherSuite,
          LeafIndex(0U),
          mapOf(),
          mapOf(NodeIndex(0U) to keyPackage.encPrivateKey).toMap(ConcurrentHashMap()),
        ),
      )

    fun new(
      cipherSuite: CipherSuite,
      leafNode: KeyPackageLeafNode,
      decryptionKey: HpkePrivateKey,
    ): RatchetTree =
      RatchetTree(
        cipherSuite,
        leafNode.newTree(),
        PrivateRatchetTree(
          cipherSuite,
          LeafIndex(0U),
          mapOf(),
          mapOf(NodeIndex(0U) to decryptionKey).toMap(ConcurrentHashMap()),
        ),
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
          PrivateRatchetTree(
            cipherSuite,
            newLeaf,
            mapOf(),
            mapOf(newLeaf.nodeIndex to decryptionKey).toMap(ConcurrentHashMap()),
          ),
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
        PrivateRatchetTree(
          cipherSuite,
          leafIndex,
          mapOf(),
          mapOf(leafIndex.nodeIndex to decryptionKey).toMap(ConcurrentHashMap()),
        ),
      )
  }
}

@JvmInline
value class PublicRatchetTree private constructor(private val nodes: Array<Node?>) : RatchetTreeOps {
  override val size: UInt
    get() = nodes.uSize
  override val root: NodeIndex
    get() = NodeIndex.root(size)

  override val indices: NodeRange
    get() = NodeIndex(0U)..<size
  override val leafNodeIndices: NodeProgression
    get() = indices step 2
  override val parentNodeIndices: NodeProgression
    get() = NodeIndex(1U)..<size step 2

  @Suppress("UNCHECKED_CAST", "kotlin:S6531")
  override val leaves: List<LeafNode<*>?>
    get() = this[leafNodeIndices] as List<LeafNode<*>?>

  override val firstBlankLeaf: LeafIndex?
    get() = leafNodeIndices.find { it.isBlank }?.leafIndex

  fun insert(newLeaf: LeafNode<*>): Pair<PublicRatchetTree, LeafIndex> =
    firstBlankLeaf
      ?.let { insertAt(newLeaf, it) }
      ?: extend().insert(newLeaf)

  internal fun insertAt(
    leafNode: LeafNode<*>,
    leafIndex: LeafIndex,
  ): Pair<PublicRatchetTree, LeafIndex> {
    val nodeIndex = leafIndex.nodeIndex
    val intermediateDirectPath = directPath(nodeIndex).dropLast(1).map { it.value.toInt() }.toSet()

    return PublicRatchetTree(
      Array(nodes.size) {
        if (it.toUInt() == nodeIndex.value) {
          leafNode
        } else if (it in intermediateDirectPath) {
          nodes[it]?.asParent?.run { copy(unmergedLeaves = unmergedLeaves + leafIndex) }
        } else {
          nodes[it]
        }
      },
    ) to leafIndex
  }

  fun remove(leafIndex: LeafIndex): PublicRatchetTree = remove(listOf(leafIndex))

  fun remove(leafIndices: List<LeafIndex>): PublicRatchetTree {
    // The specification states that only the intermediate nodes along the path are to be blanked (commented line of
    // code). Still, other implementors, including the public test vectors, blank the entire direct path of the leaf.
    //
    // Anyway, this shouldn't make any substantial difference in practice, as a Remove proposal requires an update
    // path, which will always replace the root of the tree.
    //
    // val intermediateDirectPath = directPath(leafIndex).dropLast(1).map { it.value.toInt() }.toSet()
    val directPath = leafIndices.flatMap(::directPath).map { it.value.toInt() }.toSet()
    val nodeIndices = leafIndices.map { it.nodeIndex.value.toInt() }.toSet()

    return PublicRatchetTree(
      Array(nodes.size) {
        if (it in nodeIndices || it in directPath) {
          null
        } else {
          nodes[it]
        }
      },
    ).truncateIfRequired()
  }

  fun update(
    leafIndex: LeafIndex,
    leafNode: LeafNode<*>,
  ): PublicRatchetTree =
    set(leafIndex, leafNode)
      // The specification states that only the intermediate nodes along the path are to be blanked (commented line of
      // code). Still, other implementors, including the public test vectors, blank the entire direct path of the leaf.
      //
      // Anyway, this shouldn't make any substantial difference in practice, as an Update proposal requires an update
      // path, which will always replace the root of the tree.
      //
      // .blank(directPath(leafIndex).dropLast(1))
      .blank(directPath(leafIndex))

  fun blank(indices: Iterable<TreeIndex>): PublicRatchetTree =
    indices.map { it.nodeIndex.value.toInt() }.toSet().let { blanked ->
      PublicRatchetTree(Array(nodes.size) { if (it in blanked) null else nodes[it] })
    }

  internal fun removeLeaves(leaves: Set<LeafIndex>): PublicRatchetTree {
    if (leaves.isEmpty()) return this

    val removedLeafIndices = leaves.map { it.value }.toSet()
    val removedLeafNodeIndices = leaves.map { it.nodeIndex.value.toInt() }.toSet()
    val removedLeafParentNodes = leaves.flatMap(::directPath).map { it.value.toInt() }.toSet()

    return PublicRatchetTree(
      Array(nodes.size) { idx ->
        when (idx) {
          in removedLeafNodeIndices -> null
          in removedLeafParentNodes ->
            nodes[idx]?.asParent?.run {
              copy(unmergedLeaves = unmergedLeaves.filter { it.value !in removedLeafIndices })
            }

          else -> nodes[idx]
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
    generateSequence(this) { it.leftSubtree }
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

    fun blankWithLeaves(leafCount: UInt): PublicRatchetTree {
      require(leafCount.toString(2).count { it == '1' } == 1) { "Leaf count must be a power of 2" }

      return PublicRatchetTree(Array(2 * leafCount.toInt() - 1) { null })
    }
  }
}

data class PrivateRatchetTree(
  private val cipherSuite: CipherSuite,
  val leafIndex: LeafIndex,
  internal val pathSecrets: Map<NodeIndex, Secret>,
  internal val privateKeyCache: ConcurrentMap<NodeIndex, HpkePrivateKey> = ConcurrentHashMap(),
  internal val commitSecret: Secret = Secret.zeroes(0U),
) {
  fun insertPathSecrets(
    pub: PublicRatchetTree,
    from: TreeIndex,
    pathSecret: Secret,
  ): PrivateRatchetTree {
    val fdp = pub.filteredDirectPath(from)
    val newPathSecrets =
      generateSequence(pathSecret) { cipherSuite.deriveSecret(it, "path") }
        .take(fdp.size + 1)
        .toList()

    return copy(
      pathSecrets = pathSecrets + from.nodeIndex.prependTo(fdp).zip(newPathSecrets).toMap(),
      privateKeyCache = (privateKeyCache - fdp.toSet() - from.nodeIndex).toMap(ConcurrentHashMap()),
      commitSecret = cipherSuite.deriveSecret(newPathSecrets.last(), "path"),
    )
  }

  fun add(
    nodeIndex: TreeIndex,
    pathSecret: Secret,
  ): PrivateRatchetTree =
    copy(
      pathSecrets = pathSecrets + (nodeIndex.nodeIndex to pathSecret),
      privateKeyCache = (privateKeyCache - nodeIndex.nodeIndex).toMap(ConcurrentHashMap()),
    )

  fun add(
    nodeIndex: TreeIndex,
    privateKey: HpkePrivateKey,
  ): PrivateRatchetTree =
    copy(
      pathSecrets = pathSecrets - nodeIndex.nodeIndex,
      privateKeyCache = (privateKeyCache + (nodeIndex.nodeIndex to privateKey)).toMap(ConcurrentHashMap()),
    )

  fun blank(indices: Iterable<TreeIndex>) =
    copy(
      pathSecrets = pathSecrets - indices.map { it.nodeIndex }.toSet(),
      privateKeyCache = (privateKeyCache - indices.map { it.nodeIndex }.toSet()).toMap(ConcurrentHashMap()),
    )

  fun blank(idx: TreeIndex) =
    copy(
      pathSecrets = pathSecrets - idx.nodeIndex,
      privateKeyCache = (privateKeyCache - idx.nodeIndex).toMap(ConcurrentHashMap()),
    )

  fun truncateToSize(size: UInt): PrivateRatchetTree =
    copy(
      pathSecrets = pathSecrets.filterKeys { it < size },
      privateKeyCache = privateKeyCache.filterKeys { it < size }.toMap(ConcurrentHashMap()),
    )

  fun getPrivateKey(nodeIndex: TreeIndex): HpkePrivateKey? =
    privateKeyCache.computeIfAbsent(nodeIndex.nodeIndex) {
      pathSecrets[it]?.let { cipherSuite.deriveKeyPair(cipherSuite.deriveSecret(it, "node")).private }
    }
}

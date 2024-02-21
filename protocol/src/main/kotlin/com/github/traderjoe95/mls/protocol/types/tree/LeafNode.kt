@file:Suppress("kotlin:S6531")

package com.github.traderjoe95.mls.protocol.types.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct8T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.LeafNodeExtension
import com.github.traderjoe95.mls.protocol.types.LeafNodeExtensions
import com.github.traderjoe95.mls.protocol.types.T
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode.Tbs.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeInfo
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash.Companion.eqNullable
import de.traderjoe.ulid.ULID

typealias KeyPackageLeafNode = LeafNode<LeafNodeSource.KeyPackage>
typealias CommitLeafNode = LeafNode<LeafNodeSource.Commit>
typealias UpdateLeafNode = LeafNode<LeafNodeSource.Update>

data class LeafNode<S : LeafNodeSource>(
  override val encryptionKey: HpkePublicKey,
  val verificationKey: VerificationKey,
  val credential: Credential,
  val capabilities: Capabilities,
  val source: S,
  val info: LeafNodeInfo?,
  override val extensions: LeafNodeExtensions,
  val signature: Signature,
) : HasExtensions<LeafNodeExtension<*>>(),
  Node,
  Struct8T.Shape<HpkePublicKey, VerificationKey, Credential, Capabilities, S, LeafNodeInfo?, LeafNodeExtensions, Signature> {
  override val parentHash: ParentHash?
    get() = info as? ParentHash

  val lifetime: Lifetime?
    get() = info as? Lifetime

  override fun withParentHash(parentHash: ParentHash): Node =
    if (source == LeafNodeSource.Commit) {
      copy(info = parentHash)
    } else {
      this
    }

  private fun tbs(
    groupId: ULID,
    leafIndex: LeafIndex,
  ): ByteArray =
    Tbs(
      encryptionKey,
      verificationKey,
      credential,
      capabilities,
      source,
      info,
      extensions,
      if (source != LeafNodeSource.KeyPackage) LeafNodeLocation(groupId, leafIndex) else null,
    ).encodeUnsafe()

  context(Raise<SignatureError>)
  fun verifySignature(
    groupContext: GroupContext,
    leafIndex: LeafIndex,
  ) {
    groupContext.cipherSuite.verifyWithLabel(
      verificationKey,
      "LeafNodeTBS",
      tbs(groupContext.groupId, leafIndex),
      signature,
    )
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as LeafNode<*>

    if (!encryptionKey.eq(other.encryptionKey)) return false
    if (!verificationKey.eq(other.verificationKey)) return false
    if (credential != other.credential) return false
    if (capabilities != other.capabilities) return false
    if (source != other.source) return false
    if (info != other.info) return false
    if (extensions != other.extensions) return false
    if (!signature.eq(other.signature)) return false
    if (!parentHash.eqNullable(other.parentHash)) return false
    if (lifetime != other.lifetime) return false

    return true
  }

  override fun hashCode(): Int {
    var result = encryptionKey.hashCode
    result = 31 * result + verificationKey.hashCode
    result = 31 * result + credential.hashCode()
    result = 31 * result + capabilities.hashCode()
    result = 31 * result + source.hashCode()
    result = 31 * result + (info?.hashCode() ?: 0)
    result = 31 * result + extensions.hashCode()
    result = 31 * result + signature.hashCode
    result = 31 * result + (parentHash?.hashCode ?: 0)
    result = 31 * result + (lifetime?.hashCode() ?: 0)
    return result
  }

  companion object : Encodable<LeafNode<*>> {
    @Suppress("kotlin:6531")
    override val dataT: DataType<LeafNode<*>> =
      struct("LeafNode") {
        it.field("encryption_key", HpkePublicKey.dataT)
          .field("signature_key", VerificationKey.dataT)
          .field("credential", Credential.dataT)
          .field("capabilities", Capabilities.dataT)
          .field("leaf_node_source", LeafNodeSource.T)
          .select<LeafNodeInfo?, _>(LeafNodeSource.T, "leaf_node_source") {
            case(LeafNodeSource.KeyPackage).then(Lifetime.dataT)
              .case(LeafNodeSource.Commit).then(ParentHash.dataT)
              .orElseNothing()
          }
          .field("extensions", LeafNodeExtension.dataT.extensionList())
          .field("signature", Signature.dataT)
      }.lift(::LeafNode)

    @Suppress("UNCHECKED_CAST", "kotlin:6531")
    fun <S : LeafNodeSource> t(expectedSource: S): DataType<LeafNode<S>> =
      struct("LeafNode") {
        it.field("encryption_key", HpkePublicKey.dataT)
          .field("signature_key", VerificationKey.dataT)
          .field("credential", Credential.dataT)
          .field("capabilities", Capabilities.dataT)
          .field("leaf_node_source", LeafNodeSource.T as DataType<S>, expectedSource)
          .select<LeafNodeInfo?, _>(LeafNodeSource.T, "leaf_node_source") {
            case(LeafNodeSource.KeyPackage).then(Lifetime.dataT)
              .case(LeafNodeSource.Commit).then(ParentHash.dataT)
              .orElseNothing()
          }
          .field("extensions", LeafNodeExtension.dataT.extensionList())
          .field("signature", Signature.dataT)
      }.lift(::LeafNode)

    context(ICipherSuite)
    fun keyPackage(
      encryptionKey: HpkePublicKey,
      verificationKey: VerificationKey,
      credential: Credential,
      capabilities: Capabilities,
      lifetime: Lifetime,
      extensions: LeafNodeExtensions,
      signingKey: SigningKey,
    ): KeyPackageLeafNode {
      val greasedExtensions = extensions + listOf(*Extension.grease())
      val greasedCapabilities =
        capabilities.copy(
          extensions =
            capabilities.extensions +
              greasedExtensions
                .filterNot { capabilities supportsExtension it.type }
                .map { it.type },
        )

      val signature =
        signWithLabel(
          signingKey,
          "LeafNodeTBS",
          Tbs.keyPackage(encryptionKey, verificationKey, credential, greasedCapabilities, lifetime, greasedExtensions)
            .encodeUnsafe(),
        )

      return LeafNode(
        encryptionKey,
        verificationKey,
        credential,
        greasedCapabilities,
        LeafNodeSource.KeyPackage,
        lifetime,
        greasedExtensions,
        signature,
      )
    }

    context(ICipherSuite)
    fun commit(
      encryptionKey: HpkePublicKey,
      oldLeafNode: LeafNode<*>,
      parentHash: ParentHash,
      leafIndex: LeafIndex,
      groupContext: GroupContext,
      signingKey: SigningKey,
    ): CommitLeafNode =
      signWithLabel(
        signingKey,
        "LeafNodeTBS",
        Tbs.commit(encryptionKey, oldLeafNode, parentHash, leafIndex, groupContext).encodeUnsafe(),
      ).let { signature ->
        LeafNode(
          encryptionKey,
          oldLeafNode.verificationKey,
          oldLeafNode.credential,
          oldLeafNode.capabilities,
          LeafNodeSource.Commit,
          parentHash,
          oldLeafNode.extensions,
          signature,
        )
      }

    context(GroupState.Active)
    internal fun update(
      encryptionKey: HpkePublicKey,
      oldLeafNode: LeafNode<*>,
      leafIndex: LeafIndex,
    ): UpdateLeafNode =
      signWithLabel(
        signingKey,
        "LeafNodeTBS",
        Tbs.update(encryptionKey, oldLeafNode, leafIndex, groupContext).encodeUnsafe(),
      ).let { signature ->
        LeafNode(
          encryptionKey,
          oldLeafNode.verificationKey,
          oldLeafNode.credential,
          oldLeafNode.capabilities,
          LeafNodeSource.Update,
          null,
          oldLeafNode.extensions,
          signature,
        )
      }
  }

  data class Tbs(
    val encryptionKey: HpkePublicKey,
    val verificationKey: VerificationKey,
    val credential: Credential,
    val capabilities: Capabilities,
    val source: LeafNodeSource,
    val info: LeafNodeInfo?,
    val extensions: LeafNodeExtensions,
    val location: LeafNodeLocation?,
  ) :
    Struct8T.Shape<
        HpkePublicKey,
        VerificationKey,
        Credential,
        Capabilities,
        LeafNodeSource,
        LeafNodeInfo?,
        LeafNodeExtensions,
        LeafNodeLocation?,
      > {
    companion object : Encodable<Tbs> {
      @Suppress("kotlin:6531")
      override val dataT: DataType<Tbs> =
        struct("LeafNodeTBS") {
          it.field("encryption_key", HpkePublicKey.dataT)
            .field("signature_key", VerificationKey.dataT)
            .field("credential", Credential.dataT)
            .field("capabilities", Capabilities.dataT)
            .field("leaf_node_source", LeafNodeSource.T)
            .select<LeafNodeInfo?, _>(LeafNodeSource.T, "leaf_node_source") {
              case(LeafNodeSource.KeyPackage).then(Lifetime.dataT)
                .case(LeafNodeSource.Commit).then(ParentHash.dataT)
                .orElseNothing()
            }
            .field("extensions", LeafNodeExtension.dataT.extensionList())
            .select<LeafNodeLocation?, _>(LeafNodeSource.T, "leaf_node_source") {
              case(LeafNodeSource.Update, LeafNodeSource.Commit).then(LeafNodeLocation.dataT)
                .orElseNothing()
            }
        }.lift(::Tbs)

      internal fun keyPackage(
        encryptionKey: HpkePublicKey,
        verificationKey: VerificationKey,
        credential: Credential,
        capabilities: Capabilities,
        lifetime: Lifetime,
        extensions: LeafNodeExtensions,
      ): Tbs =
        Tbs(
          encryptionKey,
          verificationKey,
          credential,
          capabilities,
          LeafNodeSource.KeyPackage,
          lifetime,
          extensions,
          null,
        )

      internal fun commit(
        encryptionKey: HpkePublicKey,
        oldLeafNode: LeafNode<*>,
        parentHash: ParentHash,
        leafIndex: LeafIndex,
        groupContext: GroupContext,
      ): Tbs =
        Tbs(
          encryptionKey,
          oldLeafNode.verificationKey,
          oldLeafNode.credential,
          oldLeafNode.capabilities,
          LeafNodeSource.Commit,
          parentHash,
          oldLeafNode.extensions,
          LeafNodeLocation(groupContext.groupId, leafIndex),
        )

      internal fun update(
        encryptionKey: HpkePublicKey,
        oldLeafNode: LeafNode<*>,
        leafIndex: LeafIndex,
        groupContext: GroupContext,
      ): Tbs =
        Tbs(
          encryptionKey,
          oldLeafNode.verificationKey,
          oldLeafNode.credential,
          oldLeafNode.capabilities,
          LeafNodeSource.Update,
          null,
          oldLeafNode.extensions,
          LeafNodeLocation(groupContext.groupId, leafIndex),
        )
    }
  }

  data class LeafNodeLocation(
    val groupId: ULID,
    val leafIndex: LeafIndex,
  ) : Struct2T.Shape<ULID, LeafIndex> {
    companion object : Encodable<LeafNodeLocation> {
      override val dataT: DataType<LeafNodeLocation> =
        struct("LeafNodeLocation") {
          it.field("group_id", ULID.T)
            .field("leaf_index", LeafIndex.dataT)
        }.lift(::LeafNodeLocation)
    }
  }
}

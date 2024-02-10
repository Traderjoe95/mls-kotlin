@file:Suppress("kotlin:S6531")

package com.github.traderjoe95.mls.protocol.types.tree

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.Struct8T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.member.orElseNothing
import com.github.traderjoe95.mls.codec.type.struct.member.then
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.type.uint32
import com.github.traderjoe95.mls.protocol.crypto.ICipherSuite
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
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
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeInfo
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import com.github.traderjoe95.mls.protocol.types.tree.leaf.ParentHash
import de.traderjoe.ulid.ULID
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

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

  context(Raise<BaseEncoderError>)
  fun tbs(
    groupId: ULID,
    leafIndex: UInt,
  ): ByteArray =
    Tbs.T.encode(
      Tbs(
        encryptionKey,
        verificationKey,
        credential,
        capabilities,
        source,
        info,
        extensions,
        if (source != LeafNodeSource.KeyPackage) LeafNodeLocation(groupId, leafIndex) else null,
      ),
    )

  context(ICipherSuite, Raise<SignatureError>)
  fun verifySignature(
    groupId: ULID,
    leafIndex: UInt,
  ) {
    verifyWithLabel(
      verificationKey,
      "LeafNodeTBS",
      EncoderError.wrap { tbs(groupId, leafIndex) },
      signature,
    )
  }

  companion object {
    @Suppress("kotlin:6531")
    val T: DataType<LeafNode<*>> =
      struct("LeafNode") {
        it.field("encryption_key", HpkePublicKey.T)
          .field("signature_key", VerificationKey.T)
          .field("credential", Credential.T)
          .field("capabilities", Capabilities.T)
          .field("leaf_node_source", LeafNodeSource.T)
          .select<LeafNodeInfo?, _>(LeafNodeSource.T, "leaf_node_source") {
            case(LeafNodeSource.KeyPackage).then(Lifetime.T)
              .case(LeafNodeSource.Commit).then(ParentHash.T)
              .orElseNothing()
          }
          .field("extensions", LeafNodeExtension.T.extensionList())
          .field("signature", Signature.T)
      }.lift(::LeafNode)

    @Suppress("UNCHECKED_CAST", "kotlin:6531")
    fun <S : LeafNodeSource> t(expectedSource: S): DataType<LeafNode<S>> =
      struct("LeafNode") {
        it.field("encryption_key", HpkePublicKey.T)
          .field("signature_key", VerificationKey.T)
          .field("credential", Credential.T)
          .field("capabilities", Capabilities.T)
          .field("leaf_node_source", LeafNodeSource.T as DataType<S>, expectedSource)
          .select<LeafNodeInfo?, _>(LeafNodeSource.T, "leaf_node_source") {
            case(LeafNodeSource.KeyPackage).then(Lifetime.T)
              .case(LeafNodeSource.Commit).then(ParentHash.T)
              .orElseNothing()
          }
          .field("extensions", LeafNodeExtension.T.extensionList())
          .field("signature", Signature.T)
      }.lift(::LeafNode)

    context(ICipherSuite, Raise<BaseEncoderError>)
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
          Tbs.T.encode(
            Tbs.keyPackage(encryptionKey, verificationKey, credential, greasedCapabilities, lifetime, greasedExtensions),
          ),
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

    context(ICipherSuite, Raise<BaseEncoderError>)
    fun commit(
      encryptionKey: HpkePublicKey,
      oldLeafNode: LeafNode<*>,
      parentHash: ParentHash,
      leafIndex: UInt,
      groupContext: GroupContext,
      signingKey: SigningKey,
    ): CommitLeafNode =
      signWithLabel(
        signingKey,
        "LeafNodeTBS",
        Tbs.T.encode(
          Tbs.commit(encryptionKey, oldLeafNode, parentHash, leafIndex, groupContext),
        ),
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

    context(GroupState, Raise<BaseEncoderError>)
    fun update(
      encryptionKey: HpkePublicKey,
      oldLeafNode: LeafNode<*>,
      leafIndex: UInt,
    ): UpdateLeafNode =
      signWithLabel(
        signingKey,
        "LeafNodeTBS",
        Tbs.T.encode(
          Tbs.update(encryptionKey, oldLeafNode, leafIndex, groupContext),
        ),
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
    companion object {
      @Suppress("UNCHECKED_CAST", "kotlin:6531")
      val T: DataType<Tbs> =
        struct("LeafNodeTBS") {
          it.field("encryption_key", HpkePublicKey.T)
            .field("signature_key", VerificationKey.T)
            .field("credential", Credential.T)
            .field("capabilities", Capabilities.T)
            .field("leaf_node_source", LeafNodeSource.T)
            .select<LeafNodeInfo?, _>(LeafNodeSource.T, "leaf_node_source") {
              case(LeafNodeSource.KeyPackage).then(Lifetime.T)
                .case(LeafNodeSource.Commit).then(ParentHash.T)
                .orElseNothing()
            }
            .field("extensions", LeafNodeExtension.T.extensionList())
            .select<LeafNodeLocation?, _>(LeafNodeSource.T, "leaf_node_source") {
              case(LeafNodeSource.Update, LeafNodeSource.Commit).then(LeafNodeLocation.T)
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
        leafIndex: UInt,
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
        leafIndex: UInt,
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
    val leafIndex: UInt,
  ) : Struct2T.Shape<ULID, UInt> {
    companion object {
      val T: DataType<LeafNodeLocation> =
        struct("LeafNodeLocation") {
          it.field("group_id", ULID.T)
            .field("leaf_index", uint32.asUInt)
        }.lift(::LeafNodeLocation)
    }
  }
}

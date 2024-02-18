package com.github.traderjoe95.mls.protocol.types.framing.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.Struct6T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtension
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage.Tbs.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource

data class KeyPackage(
  val version: ProtocolVersion,
  val cipherSuite: CipherSuite,
  val initKey: HpkePublicKey,
  val leafNode: KeyPackageLeafNode,
  override val extensions: KeyPackageExtensions,
  val signature: Signature,
) : HasExtensions<KeyPackageExtension<*>>(),
  Message,
  Struct6T.Shape<ProtocolVersion, CipherSuite, HpkePublicKey, KeyPackageLeafNode, KeyPackageExtensions, Signature> {
  context(AuthenticationService<*>, Raise<IsSameClientError>)
  suspend infix fun isSameClientAs(other: KeyPackage): Boolean = isSameClient(leafNode.credential, other.leafNode.credential).bind()

  context(Raise<SignatureError>)
  fun verifySignature() {
    cipherSuite.verifyWithLabel(
      leafNode.verificationKey,
      "KeyPackageTBS",
      Tbs(version, cipherSuite, initKey, leafNode, extensions).encodeUnsafe(),
      signature,
    )
  }

  companion object : Encodable<KeyPackage> {
    @Suppress("kotlin:S6531")
    override val dataT: DataType<KeyPackage> =
      struct("KeyPackage") {
        it.field("version", ProtocolVersion.T)
          .field("cipher_suite", CipherSuite.T)
          .field("init_key", HpkePublicKey.dataT)
          .field("leaf_node", LeafNode.t(LeafNodeSource.KeyPackage))
          .field("extensions", KeyPackageExtension.dataT.extensionList())
          .field("signature", Signature.dataT)
      }.lift(::KeyPackage)

    context(CipherSuite)
    fun create(
      initKey: HpkePublicKey,
      leafNode: KeyPackageLeafNode,
      extensions: KeyPackageExtensions,
      signingKey: SigningKey,
    ): KeyPackage {
      val greasedExtensions = extensions + listOf(*Extension.grease())

      return KeyPackage(
        ProtocolVersion.MLS_1_0,
        this@CipherSuite,
        initKey,
        leafNode,
        greasedExtensions,
        signWithLabel(
          signingKey,
          "KeyPackageTBS",
          Tbs(ProtocolVersion.MLS_1_0, this@CipherSuite, initKey, leafNode, greasedExtensions).encodeUnsafe(),
        ),
      )
    }
  }

  data class Tbs(
    val version: ProtocolVersion,
    val cipherSuite: CipherSuite,
    val initKey: HpkePublicKey,
    val leafNode: KeyPackageLeafNode,
    val extensions: KeyPackageExtensions,
  ) : Struct5T.Shape<ProtocolVersion, CipherSuite, HpkePublicKey, KeyPackageLeafNode, KeyPackageExtensions> {
    companion object : Encodable<Tbs> {
      @Suppress("kotlin:S6531")
      override val dataT: DataType<Tbs> =
        struct("KeyPackageTBS") {
          it.field("version", ProtocolVersion.T)
            .field("cipher_suite", CipherSuite.T)
            .field("init_key", HpkePublicKey.dataT)
            .field("leaf_node", LeafNode.t(LeafNodeSource.KeyPackage))
            .field("extensions", KeyPackageExtension.dataT.extensionList())
        }.lift(::Tbs)
    }
  }

  @JvmInline
  value class Ref(val ref: ByteArray) {
    val hashCode: Int
      get() = ref.contentHashCode()

    companion object : Encodable<Ref> {
      override val dataT: DataType<Ref> =
        HashReference.dataT.derive(
          { it.asRef },
          { HashReference(it.ref) },
          name = "KeyPackageRef",
        )
    }
  }
}

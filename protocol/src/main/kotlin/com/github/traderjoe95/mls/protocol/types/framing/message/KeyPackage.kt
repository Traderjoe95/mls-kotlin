package com.github.traderjoe95.mls.protocol.types.framing.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.get
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.Struct6T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.EncoderError
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
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

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
  context(Raise<BaseEncoderError>)
  fun encode(): ByteArray = T.encode(this)

  context(AuthenticationService<*>, Raise<IsSameClientError>)
  suspend infix fun isSameClientAs(other: KeyPackage): Boolean = isSameClient(leafNode.credential, other.leafNode.credential).bind()

  context(Raise<SignatureError>)
  fun verifySignature() {
    cipherSuite.verifyWithLabel(
      leafNode.verificationKey,
      "KeyPackageTBS",
      EncoderError.wrap { Tbs.T.encode(Tbs(version, cipherSuite, initKey, leafNode, extensions)) },
      signature,
    )
  }

  companion object {
    @Suppress("kotlin:S6531")
    val T: DataType<KeyPackage> =
      struct("KeyPackage") {
        it.field("version", ProtocolVersion.T)
          .field("cipher_suite", CipherSuite.T)
          .field("init_key", HpkePublicKey.T)
          .field("leaf_node", LeafNode.t(LeafNodeSource.KeyPackage))
          .field("extensions", KeyPackageExtension.T.extensionList())
          .field("signature", Signature.T)
      }.lift(::KeyPackage)

    context(CipherSuite, Raise<BaseEncoderError>)
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
          Tbs.T.encode(Tbs(ProtocolVersion.MLS_1_0, this@CipherSuite, initKey, leafNode, greasedExtensions)),
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
    companion object {
      @Suppress("kotlin:S6531")
      val T: DataType<Tbs> =
        struct("KeyPackageTBS") {
          it.field("version", ProtocolVersion.T)
            .field("cipher_suite", CipherSuite.T)
            .field("init_key", HpkePublicKey.T)
            .field("leaf_node", LeafNode.t(LeafNodeSource.KeyPackage))
            .field("extensions", KeyPackageExtension.T.extensionList())
        }.lift(::Tbs)
    }
  }

  @JvmInline
  value class Ref(val ref: ByteArray) {
    val hashCode: Int
      get() = ref.contentHashCode()

    companion object {
      val T: DataType<Ref> =
        HashReference.T.derive(
          { it.asRef },
          { HashReference(it.ref) },
          name = "KeyPackageRef",
        )
    }
  }
}

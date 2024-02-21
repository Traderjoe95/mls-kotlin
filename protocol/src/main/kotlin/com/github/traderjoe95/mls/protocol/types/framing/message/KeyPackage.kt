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
import com.github.traderjoe95.mls.protocol.error.KeyPackageMismatchError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtension
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
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
  val ref: Ref by lazy {
    cipherSuite.makeKeyPackageRef(this)
  }

  context(Raise<SignatureError>)
  fun verifySignature() {
    cipherSuite.verifyWithLabel(
      leafNode.verificationKey,
      "KeyPackageTBS",
      Tbs(version, cipherSuite, initKey, leafNode, extensions).encodeUnsafe(),
      signature,
    )
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as KeyPackage

    if (version != other.version) return false
    if (cipherSuite != other.cipherSuite) return false
    if (!initKey.eq(other.initKey)) return false
    if (leafNode != other.leafNode) return false
    if (extensions != other.extensions) return false
    if (signature.eq(other.signature)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = version.hashCode()
    result = 31 * result + cipherSuite.hashCode()
    result = 31 * result + initKey.hashCode
    result = 31 * result + leafNode.hashCode()
    result = 31 * result + extensions.hashCode()
    result = 31 * result + signature.hashCode
    return result
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

    fun eq(other: Ref): Boolean = ref.contentEquals(other.ref)

    companion object : Encodable<Ref> {
      override val dataT: DataType<Ref> =
        HashReference.dataT.derive(
          { it.asRef },
          { HashReference(it.ref) },
          name = "KeyPackageRef",
        )
    }
  }

  data class Private(
    val public: KeyPackage,
    val initPrivateKey: HpkePrivateKey,
    val encPrivateKey: HpkePrivateKey,
    val signingKey: SigningKey,
  ) {
    val cipherSuite
      get() = public.cipherSuite
    val version
      get() = public.version
    val leafNode: KeyPackageLeafNode
      get() = public.leafNode

    val initKeyPair: HpkeKeyPair
      get() = HpkeKeyPair(initPrivateKey to public.initKey)

    val ref: Ref
      get() = public.ref

    context(Raise<KeyPackageMismatchError>)
    fun checkParametersCompatible(welcome: Welcome) =
      checkParametersCompatible(version, welcome.cipherSuite)

    context(Raise<KeyPackageMismatchError>)
    fun checkParametersCompatible(groupInfo: GroupInfo) =
      checkParametersCompatible(groupInfo.groupContext.protocolVersion, groupInfo.groupContext.cipherSuite)

    context(Raise<KeyPackageMismatchError>)
    fun checkParametersCompatible(
      protocolVersion: ProtocolVersion,
      cipherSuite: CipherSuite,
    ) {
      if (protocolVersion != version) raise(KeyPackageMismatchError.ProtocolVersionMismatch(protocolVersion, version))
      if (cipherSuite != this.cipherSuite) {
        raise(
          KeyPackageMismatchError.CipherSuiteMismatch(
            cipherSuite,
            this.cipherSuite,
          ),
        )
      }
    }
  }
}

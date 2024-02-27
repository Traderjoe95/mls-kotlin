package com.github.traderjoe95.mls.protocol.message

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.Struct6T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.KeyPackageMismatchError
import com.github.traderjoe95.mls.protocol.error.SignatureError
import com.github.traderjoe95.mls.protocol.message.KeyPackage.Tbs.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.HasExtensions
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtension
import com.github.traderjoe95.mls.protocol.types.KeyPackageExtensions
import com.github.traderjoe95.mls.protocol.types.LeafNodeExtensions
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.extensionList
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.tree.KeyPackageLeafNode
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Capabilities
import com.github.traderjoe95.mls.protocol.types.tree.leaf.LeafNodeSource
import com.github.traderjoe95.mls.protocol.types.tree.leaf.Lifetime
import com.github.traderjoe95.mls.protocol.util.plus
import java.time.Instant
import kotlin.time.Duration

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
      leafNode.signaturePublicKey,
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
    if (initKey neq other.initKey) return false
    if (leafNode != other.leafNode) return false
    if (extensions != other.extensions) return false
    if (signature neq other.signature) return false

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

    fun generate(
      cipherSuite: CipherSuite,
      signatureKeyPair: SignatureKeyPair,
      credential: Credential,
      capabilities: Capabilities,
      lifetime: Duration,
      keyPackageExtensions: KeyPackageExtensions = listOf(),
      leafNodeExtensions: LeafNodeExtensions = listOf(),
    ): Private {
      val initKeyPair = cipherSuite.generateHpkeKeyPair()
      val encKeyPair = cipherSuite.generateHpkeKeyPair()

      return Private(
        create(
          cipherSuite,
          initKeyPair.public,
          LeafNode.keyPackage(
            cipherSuite,
            encKeyPair.public,
            signatureKeyPair.public,
            credential,
            capabilities,
            Lifetime(Instant.now(), Instant.now() + lifetime),
            extensions = leafNodeExtensions,
            signaturePrivateKey = signatureKeyPair.private,
          ),
          keyPackageExtensions,
          signatureKeyPair.private,
        ),
        initKeyPair.private,
        encKeyPair.private,
        signatureKeyPair.private,
      )
    }

    fun create(
      cipherSuite: CipherSuite,
      initKey: HpkePublicKey,
      leafNode: KeyPackageLeafNode,
      extensions: KeyPackageExtensions,
      signaturePrivateKey: SignaturePrivateKey,
    ): KeyPackage {
      val greasedExtensions = extensions + listOf(*Extension.grease())

      return KeyPackage(
        ProtocolVersion.MLS_1_0,
        cipherSuite,
        initKey,
        leafNode,
        greasedExtensions,
        cipherSuite.signWithLabel(
          signaturePrivateKey,
          "KeyPackageTBS",
          Tbs(ProtocolVersion.MLS_1_0, cipherSuite, initKey, leafNode, greasedExtensions).encodeUnsafe(),
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
        }.lift(KeyPackage::Tbs)
    }
  }

  @JvmInline
  value class Ref(override val bytes: ByteArray) : RefinedBytes<Ref> {
    companion object : Encodable<Ref> {
      override val dataT: DataType<Ref> = RefinedBytes.dataT(KeyPackage::Ref, name = "KeyPackageRef")
    }
  }

  data class Private(
    val public: KeyPackage,
    val initPrivateKey: HpkePrivateKey,
    val encPrivateKey: HpkePrivateKey,
    val signaturePrivateKey: SignaturePrivateKey,
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
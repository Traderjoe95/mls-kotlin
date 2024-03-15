package com.github.traderjoe95.mls.protocol.message

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct5T
import com.github.traderjoe95.mls.codec.type.struct.Struct6T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.CreateSignatureError
import com.github.traderjoe95.mls.protocol.error.KeyPackageMismatchError
import com.github.traderjoe95.mls.protocol.error.VerifySignatureError
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
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
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
  override val wireFormat: WireFormat = WireFormat.MlsKeyPackage

  @get:JvmName("ref")
  val ref: Ref by lazy { cipherSuite.makeKeyPackageRef(this) }

  override val encoded: ByteArray by lazy { encodeUnsafe() }

  fun verifySignature(): Either<VerifySignatureError, KeyPackage> =
    either {
      this@KeyPackage.apply {
        cipherSuite.verifyWithLabel(
          leafNode.signaturePublicKey,
          "KeyPackageTBS",
          Tbs(version, cipherSuite, initKey, leafNode, extensions).encodeUnsafe(),
          signature,
        )
      }
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
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<KeyPackage> =
      struct("KeyPackage") {
        it.field("version", ProtocolVersion.T)
          .field("cipher_suite", CipherSuite.T)
          .field("init_key", HpkePublicKey.T)
          .field("leaf_node", LeafNode.t(LeafNodeSource.KeyPackage))
          .field("extensions", KeyPackageExtension.T.extensionList())
          .field("signature", Signature.T)
      }.lift(::KeyPackage)

    fun generate(
      cipherSuite: CipherSuite,
      signatureKeyPair: SignatureKeyPair,
      credential: Credential,
      capabilities: Capabilities,
      lifetime: Duration,
      keyPackageExtensions: KeyPackageExtensions = listOf(),
      leafNodeExtensions: LeafNodeExtensions = listOf(),
    ): Either<CreateSignatureError, Private> =
      generate(
        cipherSuite,
        signatureKeyPair,
        credential,
        capabilities,
        Lifetime(Instant.now(), Instant.now() + lifetime),
        keyPackageExtensions,
        leafNodeExtensions,
      )

    fun generate(
      cipherSuite: CipherSuite,
      signatureKeyPair: SignatureKeyPair,
      credential: Credential,
      capabilities: Capabilities,
      lifetime: Lifetime,
      keyPackageExtensions: KeyPackageExtensions = listOf(),
      leafNodeExtensions: LeafNodeExtensions = listOf(),
    ): Either<CreateSignatureError, Private> =
      either {
        val initKeyPair = cipherSuite.generateHpkeKeyPair()
        val encKeyPair = cipherSuite.generateHpkeKeyPair()

        Private(
          create(
            cipherSuite,
            initKeyPair.public,
            LeafNode.keyPackage(
              cipherSuite,
              encKeyPair.public,
              signatureKeyPair.public,
              credential,
              capabilities,
              lifetime,
              extensions = leafNodeExtensions,
              signaturePrivateKey = signatureKeyPair.private,
            ).bind(),
            keyPackageExtensions,
            signatureKeyPair.private,
          ).bind(),
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
    ): Either<CreateSignatureError, KeyPackage> =
      either {
        val greasedExtensions = extensions + listOf(*Extension.grease())

        KeyPackage(
          ProtocolVersion.MLS_1_0,
          cipherSuite,
          initKey,
          leafNode,
          greasedExtensions,
          cipherSuite.signWithLabel(
            signaturePrivateKey,
            "KeyPackageTBS",
            Tbs(ProtocolVersion.MLS_1_0, cipherSuite, initKey, leafNode, greasedExtensions).encodeUnsafe(),
          ).bind(),
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
      @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
      override val T: DataType<Tbs> =
        struct("KeyPackageTBS") {
          it.field("version", ProtocolVersion.T)
            .field("cipher_suite", CipherSuite.T)
            .field("init_key", HpkePublicKey.T)
            .field("leaf_node", LeafNode.t(LeafNodeSource.KeyPackage))
            .field("extensions", KeyPackageExtension.T.extensionList())
        }.lift(KeyPackage::Tbs)
    }
  }

  @JvmInline
  value class Ref(override val bytes: ByteArray) : RefinedBytes<Ref> {
    companion object : Encodable<Ref> {
      @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
      override val T: DataType<Ref> = RefinedBytes.dataT(KeyPackage::Ref, name = "KeyPackageRef")
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
      get() = HpkeKeyPair(initPrivateKey, public.initKey)

    val ref: Ref
      get() = public.ref

    context(Raise<KeyPackageMismatchError>)
    fun checkParametersCompatible(welcome: Welcome) =
      checkParametersCompatible(version, welcome.cipherSuite)

    context(Raise<KeyPackageMismatchError>)
    fun checkParametersCompatible(groupInfo: GroupInfo) =
      checkParametersCompatible(groupInfo.groupContext.protocolVersion, groupInfo.cipherSuite)

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

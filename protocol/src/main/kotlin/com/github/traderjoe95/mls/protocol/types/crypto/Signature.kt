package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.protocol.types.MoveCopyWipe
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.util.wipe

@JvmInline
value class SignaturePrivateKey(override val bytes: ByteArray) :
  RefinedBytes<SignaturePrivateKey>,
  MoveCopyWipe<SignaturePrivateKey> {
  override fun copy(): SignaturePrivateKey = SignaturePrivateKey(bytes.copyOf())

  override fun wipe() {
    bytes.wipe()
  }

  companion object {
    val ByteArray.asSignaturePrivateKey: SignaturePrivateKey
      get() = SignaturePrivateKey(this)
  }
}

@JvmInline
value class SignaturePublicKey(override val bytes: ByteArray) : RefinedBytes<SignaturePublicKey> {
  companion object : Encodable<SignaturePublicKey> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<SignaturePublicKey> =
      RefinedBytes.dataT(::SignaturePublicKey, name = "SignaturePublicKey")

    val ByteArray.asSignaturePublicKey: SignaturePublicKey
      get() = SignaturePublicKey(this)
  }
}

data class SignatureKeyPair(
  val private: SignaturePrivateKey,
  val public: SignaturePublicKey,
) : MoveCopyWipe<SignatureKeyPair> {
  override fun copy(): SignatureKeyPair = SignatureKeyPair(private.copy(), public)

  override fun wipe() {
    private.wipe()
  }
}

@JvmInline
value class Signature(override val bytes: ByteArray) : RefinedBytes<Signature> {
  companion object : Encodable<Signature> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<Signature> = RefinedBytes.dataT(::Signature)

    val ByteArray.asSignature: Signature
      get() = Signature(this)
  }
}

internal data class SignContent(val label: String, val content: ByteArray) : Struct2T.Shape<String, ByteArray> {
  companion object : Encodable<SignContent> {
    @Suppress("kotlin:S6531", "ktlint:standard:property-naming")
    override val T: DataType<SignContent> = bytesAndLabel("SignContent", "content").lift(::SignContent)

    fun create(
      label: String,
      content: ByteArray,
    ): SignContent = SignContent("MLS 1.0 $label", content)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as SignContent

    if (label != other.label) return false
    if (!content.contentEquals(other.content)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = label.hashCode()
    result = 31 * result + content.contentHashCode()
    return result
  }
}

package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift

@JvmInline
value class SigningKey(val key: ByteArray)

@JvmInline
value class VerificationKey(val key: ByteArray) {
  val hashCode: Int
    get() = key.contentHashCode()

  fun eq(other: VerificationKey): Boolean = key.contentEquals(other.key)

  companion object : Encodable<VerificationKey> {
    override val dataT: DataType<VerificationKey> = opaque[V].derive({ VerificationKey(it) }, { it.key }, name = "SignaturePublicKey")
  }
}

@JvmInline
value class Signature(val value: ByteArray) {
  val hashCode: Int
    get() = value.contentHashCode()

  fun eq(other: Signature): Boolean = value.contentEquals(other.value)

  companion object : Encodable<Signature> {
    override val dataT: DataType<Signature> = opaque[V].derive({ Signature(it) }, { it.value })

    val ByteArray.asSignature: Signature
      get() = Signature(this)
  }
}

internal data class SignContent(val label: String, val content: ByteArray) : Struct2T.Shape<String, ByteArray> {
  companion object : Encodable<SignContent> {
    override val dataT: DataType<SignContent> = bytesAndLabel("SignContent", "content").lift(::SignContent)

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

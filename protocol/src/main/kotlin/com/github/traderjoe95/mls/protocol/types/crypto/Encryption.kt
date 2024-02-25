package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.lift
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.util.fromBytes
import com.github.traderjoe95.mls.codec.util.toBytes
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.util.wipe
import java.security.SecureRandom
import kotlin.experimental.xor

@JvmInline
value class HpkePrivateKey(override val bytes: ByteArray) : RefinedBytes<HpkePrivateKey> {
  fun move() = copy().also { wipe() }

  fun copy() = HpkePrivateKey(bytes.copyOf())

  fun wipe() = bytes.wipe()

  companion object {
    val ByteArray.asHpkePrivateKey: HpkePrivateKey
      get() = HpkePrivateKey(this)
  }
}

@JvmInline
value class HpkePublicKey(override val bytes: ByteArray) : RefinedBytes<HpkePublicKey> {
  companion object : Encodable<HpkePublicKey> {
    override val dataT: DataType<HpkePublicKey> = RefinedBytes.dataT(::HpkePublicKey, name = "HPKEPublicKey")

    val ByteArray.asHpkePublicKey: HpkePublicKey
      get() = HpkePublicKey(this)
  }
}

@JvmInline
value class HpkeKeyPair(private val keyPair: Pair<HpkePrivateKey, HpkePublicKey>) {
  constructor(privateKey: HpkePrivateKey, publicKey: HpkePublicKey) : this(privateKey to publicKey)

  val private: HpkePrivateKey
    get() = keyPair.first

  val public: HpkePublicKey
    get() = keyPair.second

  operator fun component1(): HpkePrivateKey = keyPair.first

  operator fun component2(): HpkePublicKey = keyPair.second
}

@JvmInline
value class Nonce(override val bytes: ByteArray) : RefinedBytes<Nonce> {
  val size: UInt
    get() = bytes.uSize

  infix fun xor(reuseGuard: ReuseGuard): Nonce =
    Nonce(
      bytes.mapIndexed { index, byte ->
        when (index) {
          0 -> byte xor (reuseGuard.value shr 24).toByte()
          1 -> byte xor (reuseGuard.value shr 16).toByte()
          2 -> byte xor (reuseGuard.value shr 8).toByte()
          3 -> byte xor reuseGuard.value.toByte()
          else -> byte
        }
      }.toByteArray(),
    )

  fun wipe(): Unit = bytes.wipe()

  companion object : Encodable<Nonce> {
    override val dataT: DataType<Nonce> = RefinedBytes.dataT(::Nonce)

    val ByteArray.asNonce: Nonce
      get() = Nonce(this)
  }
}

@JvmInline
value class ReuseGuard(val value: Int) {
  companion object : Encodable<ReuseGuard> {
    private val RANDOM = SecureRandom()

    override val dataT: DataType<ReuseGuard> =
      opaque[4U].derive(
        { ReuseGuard(Int.fromBytes(it)) },
        { it.value.toBytes(4U) },
      )

    fun random(random: SecureRandom = RANDOM): ReuseGuard = ReuseGuard(random.nextInt())
  }
}

@JvmInline
value class Aad(override val bytes: ByteArray) : RefinedBytes<Aad> {
  companion object {
    val empty: Aad
      get() = Aad(byteArrayOf())

    val ByteArray.asAad: Aad
      get() = Aad(this)
  }
}

@JvmInline
value class Ciphertext(override val bytes: ByteArray) : RefinedBytes<Ciphertext> {
  val size: Int
    get() = bytes.size

  companion object : Encodable<Ciphertext> {
    override val dataT: DataType<Ciphertext> = RefinedBytes.dataT(::Ciphertext)

    val ByteArray.asCiphertext: Ciphertext
      get() = Ciphertext(this)
  }
}

@JvmInline
value class KemOutput(override val bytes: ByteArray) : RefinedBytes<KemOutput> {
  val size: Int
    get() = bytes.size

  companion object : Encodable<KemOutput> {
    override val dataT: DataType<KemOutput> = RefinedBytes.dataT(::KemOutput)

    val ByteArray.asKemOutput: KemOutput
      get() = KemOutput(this)
  }
}

data class HpkeCiphertext(
  val kemOutput: KemOutput,
  val ciphertext: Ciphertext,
) : Struct2T.Shape<KemOutput, Ciphertext> {
  companion object : Encodable<HpkeCiphertext> {
    override val dataT: DataType<HpkeCiphertext> =
      struct("HPKECiphertext") {
        it.field("kem_output", KemOutput.dataT)
          .field("ciphertext", Ciphertext.dataT)
      }.lift(::HpkeCiphertext)
  }
}

internal data class EncryptContext(val label: String, val context: ByteArray) : Struct2T.Shape<String, ByteArray> {
  companion object : Encodable<EncryptContext> {
    override val dataT = bytesAndLabel("EncryptContext", "context").lift(::EncryptContext)

    fun create(
      label: String,
      context: ByteArray,
    ): EncryptContext = EncryptContext("MLS 1.0 $label", context)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as SignContent

    if (label != other.label) return false
    if (!context.contentEquals(other.content)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = label.hashCode()
    result = 31 * result + context.contentHashCode()
    return result
  }
}

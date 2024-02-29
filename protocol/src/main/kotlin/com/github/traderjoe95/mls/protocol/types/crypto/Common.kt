package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.asUtf8String
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.types.MoveCopyWipe
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce.Companion.asNonce
import com.github.traderjoe95.mls.protocol.util.wipe

@JvmInline
value class Secret(override val bytes: ByteArray) : RefinedBytes<Secret>, MoveCopyWipe<Secret> {
  override fun copy(): Secret = Secret(bytes.copyOf())

  val asNonce: Nonce
    get() = bytes.asNonce

  override fun wipe(): Unit = bytes.wipe()

  companion object : Encodable<Secret> {
    override val dataT: DataType<Secret> = RefinedBytes.dataT(::Secret)

    val ByteArray.asSecret: Secret
      get() = Secret(this)

    fun zeroes(length: UInt): Secret = Secret(ByteArray(length.toInt()))

    fun zeroes(length: UShort): Secret = Secret(ByteArray(length.toInt()))
  }
}

internal fun bytesAndLabel(
  structName: String,
  contentName: String,
): Struct2T<String, ByteArray> =
  struct(structName) {
    it.field("label", opaque[V].asUtf8String)
      .field(contentName, opaque[V])
  }

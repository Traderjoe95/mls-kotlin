package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.asUtf8String
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque
import com.github.traderjoe95.mls.codec.type.struct.Struct2T
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce.Companion.asNonce
import com.github.traderjoe95.mls.protocol.util.wipe

@JvmInline
value class Secret(val key: ByteArray) {
  val asNonce: Nonce
    get() = key.asNonce

  fun wipe(): Unit = key.wipe()

  companion object : Encodable<Secret> {
    override val dataT: DataType<Secret> = opaque[V].derive({ it.asSecret }, { it.key })
    val ByteArray.asSecret: Secret
      get() = Secret(this)

    fun zeroes(length: UInt): Secret = Secret(ByteArray(length.toInt()))
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

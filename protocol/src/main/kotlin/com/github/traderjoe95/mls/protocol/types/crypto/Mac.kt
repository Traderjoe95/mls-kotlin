package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.type.V
import com.github.traderjoe95.mls.codec.type.derive
import com.github.traderjoe95.mls.codec.type.opaque

@JvmInline
value class Mac(val value: ByteArray) {
  companion object {
    val T: DataType<Mac> = opaque[V].derive({ Mac(it) }, { it.value }, name = "MAC")

    val ByteArray.asMac: Mac
      get() = Mac(this)
  }
}

package com.github.traderjoe95.mls.protocol.types.crypto

import com.github.traderjoe95.mls.codec.Encodable
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.protocol.types.RefinedBytes

@JvmInline
value class Mac(override val bytes: ByteArray) : RefinedBytes<Mac> {
  companion object : Encodable<Mac> {
    override val dataT: DataType<Mac> = RefinedBytes.dataT(::Mac, name = "MAC")

    val ByteArray.asMac: Mac
      get() = Mac(this)
  }
}

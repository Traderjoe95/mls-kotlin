package com.github.traderjoe95.mls.codec

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.DataType

interface Encodable<T> {
  val dataT: DataType<T>

  context(Raise<EncoderError>)
  fun T.encode(): ByteArray = dataT.encode(this)

  fun T.encodeUnsafe(): ByteArray = dataT.encodeUnsafe(this)

  context(Raise<DecoderError>)
  fun decode(bytes: ByteArray): T = bytes.decodeAs(dataT)
}

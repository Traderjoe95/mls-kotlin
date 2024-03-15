package com.github.traderjoe95.mls.codec

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.DataType
import com.github.traderjoe95.mls.codec.util.throwAnyError

interface Encodable<T> {
  @Suppress("PropertyName")
  val T: DataType<T>

  fun T.encode(): Either<EncoderError, ByteArray> = either { T.encode(this@encode) }

  fun T.encodeUnsafe(): ByteArray = T.encodeUnsafe(this)

  context(Raise<DecoderError>)
  fun decode(bytes: ByteArray): T = bytes.decodeAs(T)

  fun decodeUnsafe(bytes: ByteArray): T = throwAnyError { decode(bytes) }
}

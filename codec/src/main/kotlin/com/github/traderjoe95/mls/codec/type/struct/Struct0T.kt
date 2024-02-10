package com.github.traderjoe95.mls.codec.type.struct

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Struct0
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.util.Slice

internal data object Struct0T : StructT<Struct0?>("struct {}") {
  context(Raise<EncoderError>)
  override fun encode(value: Struct0?): ByteArray = byteArrayOf()

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<Struct0?, Slice> = null to bytes

  fun create(): Struct0? = null

  override fun toString(): String = name
}

package com.github.traderjoe95.mls.codec.type.struct.member

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.Struct
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.type.struct.StructT
import com.github.traderjoe95.mls.codec.util.Slice

sealed class Member<V> {
  abstract val index: UInt

  abstract val encodedLength: UInt?

  context(Raise<EncoderError>)
  internal abstract fun encodeValue(
    value: V,
    struct: Struct,
    structT: StructT<*>,
  ): ByteArray

  context(Raise<DecoderError>)
  internal abstract fun decodeValue(
    bytes: Slice,
    alreadyDecoded: Struct?,
    structT: StructT<*>,
  ): Pair<V, Slice>
}

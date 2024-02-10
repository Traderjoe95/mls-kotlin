package com.github.traderjoe95.mls.codec.type

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.LengthError
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.util.uSize

val opaque: OpaqueT.Companion = OpaqueT

val OpaqueT.asUtf8String: DataType<String>
  get() = derive({ it.decodeToString() }, { it.encodeToByteArray() })

data class OpaqueT internal constructor(val length: Length) : DataType<ByteArray> {
  override val name: String = "opaque${length.name}"
  override val encodedLength: UInt? = length.vectorEncodedLength

  context(Raise<EncoderError>)
  override fun encode(value: ByteArray): ByteArray = length.encode(value.uSize) + value

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<ByteArray, Slice> =
    length.decode(bytes).let { (length, remaining) ->
      remaining.take(length)
    }

  companion object {
    operator fun get(length: (DataType<*>) -> VariableLength): OpaqueT = OpaqueT(length(uint8))

    operator fun get(fixedLength: UInt): OpaqueT = throwAnyError { OpaqueT(FixedLength.of(fixedLength, UInt8T)) }

    context(Raise<LengthError>)
    operator fun get(intervalLength: UIntRange): OpaqueT = OpaqueT(IntervalLength.of(intervalLength, UInt8T))
  }
}

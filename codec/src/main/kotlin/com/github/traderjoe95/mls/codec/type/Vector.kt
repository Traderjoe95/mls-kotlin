package com.github.traderjoe95.mls.codec.type

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.LengthError
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.uSize

operator fun <V> DataType<V>.get(length: (DataType<*>) -> VariableLength): DataType<List<V>> = vector(length)

fun <V> DataType<V>.vector(length: (DataType<*>) -> VariableLength): DataType<List<V>> = VectorT(this, length(this))

context(Raise<LengthError>)
operator fun <V> DataType<V>.get(fixedLength: UInt): DataType<List<V>> = vector(fixedLength)

context(Raise<LengthError>)
fun <V> DataType<V>.vector(fixedLength: UInt): DataType<List<V>> =
  VectorT(this, FixedLength.of(fixedLength, this))

context(Raise<LengthError>)
operator fun <V> DataType<V>.get(intervalLength: UIntRange): DataType<List<V>> = vector(intervalLength)

context(Raise<LengthError>)
fun <V> DataType<V>.vector(intervalLength: UIntRange): DataType<List<V>> =
  VectorT(this, IntervalLength.of(intervalLength, this))

data class VectorT<V> internal constructor(
  val componentType: DataType<V>,
  val length: Length,
) : DataType<List<V>> {
  override val name: String = "${componentType.name}${length.name}"
  override val encodedLength: UInt? = length.vectorEncodedLength

  context(Raise<EncoderError>)
  override fun encode(value: List<V>): ByteArray =
    encodeVector(value, componentType).let {
      with(length) { encode(it.uSize) } + it
    }

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<List<V>, Slice> =
    length.decode(bytes).let { (length, data) ->
      data.takeSlice(length) { vector ->
        var remainingVector = vector

        val items = mutableListOf<V>()
        while (remainingVector.hasRemaining) {
          val (head, tail) = with(componentType) { decode(remainingVector) }

          items += head
          remainingVector = tail
        }

        remainingVector.ensureFinished()
        items.toList()
      }
    }

  companion object {
    context(Raise<EncoderError>)
    internal fun <T> encodeVector(
      vector: List<T>,
      valueType: DataType<T>,
    ): ByteArray =
      if (vector.isEmpty()) {
        byteArrayOf()
      } else {
        vector.asSequence().map { valueType.encode(it) }.reduce(ByteArray::plus)
      }
  }
}

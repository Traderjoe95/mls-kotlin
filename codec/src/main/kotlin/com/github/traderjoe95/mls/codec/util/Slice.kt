package com.github.traderjoe95.mls.codec.util

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.SliceError

val ByteArray.full: Slice
  get() = Slice.of(this)

context(Raise<SliceError>)
fun ByteArray.partial(range: UIntRange): Slice = Slice.of(this, range)

context(Raise<SliceError>)
fun ByteArray.partial(startIndex: UInt): Slice = Slice.of(this, startIndex)

@JvmInline
value class Slice private constructor(private val dataAndRange: Pair<ByteArray, UIntRange>) {
  private val full: ByteArray
    get() = dataAndRange.first
  private val range: UIntRange
    get() = dataAndRange.second
  val data: ByteArray
    get() = full[range.normalized]

  val firstIndex: UInt
    get() = if (full.isEmpty()) 0U else range.first
  val lastIndex: UInt
    get() = range.last

  val size: UInt
    get() = if (full.isEmpty() || range.isEmpty()) 0U else lastIndex - firstIndex + 1U
  val hasRemaining: Boolean
    get() = size > 0U

  val first: Byte
    get() = full[firstIndex.toInt()]

  @PublishedApi internal fun hasRemaining(bytes: UInt): Boolean = size >= bytes

  context(Raise<DecoderError>)
  fun takeNext(): Pair<Byte, Slice> = take(1U) { it[0] }

  context(Raise<DecoderError>)
  inline fun <T> takeNext(crossinline block: Raise<DecoderError>.(Byte) -> T): Pair<T, Slice> = take(1U) { block(it[0]) }

  context(Raise<DecoderError>)
  fun take(count: UInt): Pair<ByteArray, Slice> = takeSlice(count).mapFirst { it.data }

  context(Raise<DecoderError>)
  inline fun <T> take(
    count: UInt,
    crossinline block: Raise<DecoderError>.(ByteArray) -> T,
  ): Pair<T, Slice> = takeSlice(count) { block(it.data) }

  context(Raise<DecoderError>)
  fun takeSlice(count: UInt): Pair<Slice, Slice> = takeSlice(count) { it }

  context(Raise<DecoderError>)
  inline fun <T> takeSlice(
    count: UInt,
    crossinline block: Raise<DecoderError>.(Slice) -> T,
  ): Pair<T, Slice> =
    if (!hasRemaining(count)) {
      raise(DecoderError.PrematureEndOfStream(firstIndex, count, size))
    } else {
      this@Raise.block(subSlice(firstIndex..<(firstIndex + count))) to advance(count)
    }

  context(Raise<DecoderError>)
  @PublishedApi internal fun advance(count: UInt): Slice = if (count == 0U) this else subSlice((firstIndex + count)..lastIndex)

  context(Raise<DecoderError>)
  @PublishedApi internal fun subSlice(indices: UIntRange): Slice = if (indices == range) this else Slice(full to indices)

  context(Raise<DecoderError>)
  operator fun component1(): Byte = this[0U]

  context(Raise<DecoderError>)
  operator fun component2(): Byte = this[1U]

  context(Raise<DecoderError>)
  operator fun component3(): Byte = this[2U]

  context(Raise<DecoderError>)
  operator fun component4(): Byte = this[3U]

  context(Raise<DecoderError>)
  operator fun component5(): Byte = this[4U]

  context(Raise<DecoderError>)
  operator fun component6(): Byte = this[5U]

  context(Raise<DecoderError>)
  operator fun component7(): Byte = this[6U]

  context(Raise<DecoderError>)
  operator fun component8(): Byte = this[7U]

  context(Raise<DecoderError>)
  operator fun get(index: UInt): Byte =
    if (!hasRemaining(index + 1U)) {
      raise(DecoderError.PrematureEndOfStream(firstIndex, index + 1U, size))
    } else {
      full[firstIndex + index]
    }

  context(Raise<DecoderError>)
  fun ensureFinished() {
    if (hasRemaining) raise(DecoderError.ExtraDataInStream(firstIndex, size))
  }

  companion object {
    internal fun of(bytes: ByteArray): Slice = Slice(bytes to bytes.indices.toUIntRange())

    context(Raise<SliceError>)
    internal fun of(
      bytes: ByteArray,
      startIndex: UInt,
    ): Slice =
      if (startIndex > bytes.uSize) {
        raise(SliceError.IndexOutOfBounds(bytes.uSize, startIndex))
      } else {
        Slice(bytes to startIndex..<bytes.uSize)
      }

    context(Raise<SliceError>)
    internal fun of(
      bytes: ByteArray,
      indices: UIntRange,
    ): Slice =
      if (indices.isNotEmpty() && indices.first >= bytes.uSize) {
        raise(SliceError.IndexOutOfBounds(bytes.uSize, indices.first))
      } else if (indices.isNotEmpty() && indices.last >= bytes.uSize) {
        raise(SliceError.IndexOutOfBounds(bytes.uSize, indices.last))
      } else {
        Slice(bytes to indices)
      }

    private fun IntRange.toUIntRange(): UIntRange =
      if (isEmpty()) {
        UIntRange(1U, 0U)
      } else {
        (first.toUInt()..last.toUInt()).normalized
      }

    internal val UIntRange.normalized: UIntRange
      get() = if (isEmpty()) UIntRange(1U, 0U) else this
  }
}

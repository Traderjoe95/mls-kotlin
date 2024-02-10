package com.github.traderjoe95.mls.codec.type

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.LengthError
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.byteLength
import com.github.traderjoe95.mls.codec.util.fromBytes
import com.github.traderjoe95.mls.codec.util.toBytes
import kotlin.experimental.xor

val V: (DataType<*>) -> VariableLength = VariableLength.Companion::of

sealed class Length : DataType<UInt> {
  open val vectorEncodedLength: UInt?
    get() = null
}

class FixedLength private constructor(internal val fixedLength: UInt) : Length() {
  override val name: String = "[$fixedLength]"
  override val encodedLength: UInt = 0U

  override val vectorEncodedLength: UInt = fixedLength

  context(Raise<EncoderError>)
  override fun encode(value: UInt): ByteArray = if (value == fixedLength) ByteArray(0) else raise(EncoderError.BadLength)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt, Slice> = fixedLength to bytes

  override fun toString(): String = name

  companion object {
    context(Raise<LengthError>)
    fun of(
      fixedLength: UInt,
      dataType: DataType<*>,
    ): FixedLength =
      dataType.encodedLength?.let {
        if (fixedLength % it != 0U) {
          raise(LengthError.BadLength(fixedLength, dataType.name, it))
        } else {
          FixedLength(fixedLength)
        }
      } ?: raise(LengthError.UndefinedLength("fixed", dataType.name))
  }
}

class IntervalLength private constructor(
  internal val range: UIntRange,
  internal val mod: UInt,
) : Length() {
  private val byteLength: UInt = range.last.byteLength

  override val name: String = "<$range>"
  override val encodedLength: UInt
    get() = byteLength

  context(Raise<EncoderError>)
  override fun encode(value: UInt): ByteArray =
    if (value in range && value % mod == 0U) value.toBytes(byteLength) else raise(EncoderError.BadLength)

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt, Slice> =
    bytes.take(byteLength) { UInt.fromBytes(it) }.also { (length, _) ->
      if (length !in range || length % mod != 0U) {
        raise(DecoderError.BadLength(bytes.firstIndex, length, range, mod))
      }
    }

  override fun toString(): String = name

  companion object {
    context(Raise<LengthError>)
    fun of(
      range: UIntRange,
      dataType: DataType<*>,
    ): IntervalLength =
      if (range.isEmpty()) {
        raise(LengthError.BadRange(range))
      } else {
        dataType.encodedLength?.let {
          if (range.first % it != 0U) {
            raise(LengthError.BadLength(range.first, dataType.name, it))
          } else if (range.last % it != 0U) {
            raise(LengthError.BadLength(range.last, dataType.name, it))
          } else {
            IntervalLength(range, it)
          }
        } ?: raise(LengthError.UndefinedLength("interval", dataType.name))
      }
  }
}

class VariableLength internal constructor(internal val mod: UInt?) : Length() {
  override val name: String = "<V>"

  context(Raise<EncoderError>)
  override fun encode(value: UInt): ByteArray =
    if (mod != null && value % mod != 0U) {
      raise(EncoderError.BadLength)
    } else {
      when (value) {
        in 0x0U..0x3FU -> byteArrayOf(value.toByte())
        in 0x40U..0x3FFFU -> (0x00004000U or value).toBytes(2U)
        in 0x4000U..0x3FFFFFFFU -> (0x80000000U or value).toBytes(4U)
        else -> raise(EncoderError.BadLength)
      }
    }

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt, Slice> =
    bytes.takeNext().let { (first, remaining) ->
      when (first.toInt() and 0xC0) {
        0x00 -> first.toUByte().toUInt() to remaining
        0x40 -> remaining.takeNext { second -> UInt.fromBytes(first xor 0x40.toByte(), second) }
        0x80 -> remaining.take(3U) { UInt.fromBytes(byteArrayOf(first xor 0x80.toByte(), *it)) }
        else -> raise(DecoderError.InvalidLengthEncoding(bytes.firstIndex))
      }
    }.also { (length, _) ->
      mod?.let {
        if (length % it != 0U) raise(DecoderError.BadLength(bytes.firstIndex, length, 0U..0x3FFFFFFFU, it))
      }
    }

  override fun toString(): String = name

  companion object {
    fun of(dataType: DataType<*>): VariableLength = VariableLength(dataType.encodedLength)
  }
}

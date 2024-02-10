package com.github.traderjoe95.mls.codec

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.IntegerError
import com.github.traderjoe95.mls.codec.type.uint24
import com.github.traderjoe95.mls.codec.util.shrToByte

interface UIntType {
  fun encode(): ByteArray

  fun toByte(): Byte

  fun toInt(): Int

  fun toLong(): Long
}

@JvmInline
value class UInt8(val data: UByte) : UIntType {
  override fun encode(): ByteArray = byteArrayOf(data.toByte())

  override fun toByte(): Byte = data.toByte()

  override fun toInt(): Int = data.toInt()

  override fun toLong(): Long = data.toLong()
}

@JvmInline
value class UInt16 private constructor(val data: UInt) : UIntType {
  // Representing this as UInt is more efficient in terms of conversions:
  // UShort would need to be converted to Int first, before being able to call shr
  // UInt already is an Int internally

  constructor(data: UShort) : this(data.toUInt())

  override fun encode(): ByteArray =
    byteArrayOf(
      data shrToByte 8,
      data.toByte(),
    )

  override fun toByte(): Byte = data.toByte()

  override fun toInt(): Int = data.toInt()

  override fun toLong(): Long = data.toLong()

  infix fun shrToByte(bitCount: Int): Byte = data shrToByte bitCount
}

@JvmInline
value class UInt24 private constructor(val data: UInt) : UIntType {
  override fun encode(): ByteArray =
    byteArrayOf(
      data shrToByte 16,
      data shrToByte 8,
      data.toByte(),
    )

  override fun toByte(): Byte = data.toByte()

  override fun toInt(): Int = data.toInt()

  override fun toLong(): Long = data.toLong()

  infix fun shrToByte(bitCount: Int): Byte = data shrToByte bitCount

  companion object {
    context(Raise<IntegerError>)
    fun of(data: UInt) =
      if (data <= 0x00FFFFFFU) {
        UInt24(data)
      } else {
        raise(IntegerError.ValueTooBig(uint24.name, data))
      }
  }
}

@JvmInline
value class UInt32(val data: UInt) : UIntType {
  override fun encode(): ByteArray =
    byteArrayOf(
      data shrToByte 24,
      data shrToByte 16,
      data shrToByte 8,
      data.toByte(),
    )

  override fun toByte(): Byte = data.toByte()

  override fun toInt(): Int = data.toInt()

  override fun toLong(): Long = data.toLong()

  infix fun shrToByte(bitCount: Int): Byte = data shrToByte bitCount
}

@JvmInline
value class UInt64(val data: ULong) : UIntType {
  override fun encode(): ByteArray =
    byteArrayOf(
      data shrToByte 56,
      data shrToByte 48,
      data shrToByte 40,
      data shrToByte 32,
      data shrToByte 24,
      data shrToByte 16,
      data shrToByte 8,
      data.toByte(),
    )

  override fun toByte(): Byte = data.toByte()

  override fun toInt(): Int = data.toInt()

  override fun toLong(): Long = data.toLong()

  infix fun shrToByte(bitCount: Int): Byte = data shrToByte bitCount
}

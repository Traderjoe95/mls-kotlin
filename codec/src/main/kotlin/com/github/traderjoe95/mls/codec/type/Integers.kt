package com.github.traderjoe95.mls.codec.type

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.UInt16
import com.github.traderjoe95.mls.codec.UInt24
import com.github.traderjoe95.mls.codec.UInt32
import com.github.traderjoe95.mls.codec.UInt64
import com.github.traderjoe95.mls.codec.UInt8
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.IntegerError
import com.github.traderjoe95.mls.codec.util.Slice
import com.github.traderjoe95.mls.codec.util.fromBytes

val uint8: UInt8T = UInt8T
val uint16: UInt16T = UInt16T
val uint24: UInt24T = UInt24T
val uint32: UInt32T = UInt32T
val uint64: UInt64T = UInt64T

data object UInt8T : DataType<UInt8> {
  override val name: String = "uint8"
  override val encodedLength: UInt = 1U

  context(Raise<EncoderError>)
  override fun encode(value: UInt8): ByteArray = value.encode()

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt8, Slice> = bytes.takeNext { UInt8(it.toUByte()) }

  val asUByte: DataType<UByte> = derive({ it.data }, { UInt8(it) })

  operator fun invoke(value: UByte): UInt8 = UInt8(value)
}

data object UInt16T : DataType<UInt16> {
  override val name: String = "uint16"
  override val encodedLength: UInt = 2U

  context(Raise<EncoderError>)
  override fun encode(value: UInt16): ByteArray = value.encode()

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt16, Slice> = bytes.take(2U) { (msb, lsb) -> UInt16(UShort.fromBytes(msb, lsb)) }

  val asUShort: DataType<UShort> = derive({ it.data.toUShort() }, { UInt16(it) })

  operator fun invoke(value: UShort): UInt16 = UInt16(value)
}

data object UInt24T : DataType<UInt24> {
  override val name: String = "uint24"
  override val encodedLength: UInt = 3U

  context(Raise<EncoderError>)
  override fun encode(value: UInt24): ByteArray = value.encode()

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt24, Slice> = bytes.take(3U) { (msb, b2, lsb) -> UInt24.of(UInt.fromBytes(msb, b2, lsb)) }

  val asUInt: DataType<UInt> = derive({ it.data }, { UInt24.of(it) })

  context(Raise<IntegerError>)
  operator fun invoke(value: UInt): UInt24 = UInt24.of(value)
}

data object UInt32T : DataType<UInt32> {
  override val name: String = "uint32"
  override val encodedLength: UInt = 4U

  context(Raise<EncoderError>)
  override fun encode(value: UInt32): ByteArray = value.encode()

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt32, Slice> = bytes.take(4U) { UInt32(UInt.fromBytes(it)) }

  val asUInt: DataType<UInt> = derive({ it.data }, { UInt32(it) })

  operator fun invoke(value: UInt): UInt32 = UInt32(value)
}

data object UInt64T : DataType<UInt64> {
  override val name: String = "uint64"
  override val encodedLength: UInt = 8U

  context(Raise<EncoderError>)
  override fun encode(value: UInt64): ByteArray = value.encode()

  context(Raise<DecoderError>)
  override fun decode(bytes: Slice): Pair<UInt64, Slice> = bytes.take(8U) { UInt64(ULong.fromBytes(it)) }

  val asULong: DataType<ULong> = derive({ it.data }, { UInt64(it) })

  operator fun invoke(value: ULong): UInt64 = UInt64(value)
}

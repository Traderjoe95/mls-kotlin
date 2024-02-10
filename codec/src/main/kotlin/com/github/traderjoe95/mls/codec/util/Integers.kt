package com.github.traderjoe95.mls.codec.util

val UInt.byteLength: UInt
  get() = toInt().byteLength
val Int.byteLength: UInt
  get() =
    when (this) {
      in 0x00000000..0x000000FF -> 1U
      in 0x00000100..0x0000FFFF -> 2U
      in 0x00010000..0x00FFFFFF -> 3U
      else -> 4U
    }

fun UInt.toBytes(length: UInt): ByteArray = toInt().toBytes(length)

fun Int.toBytes(length: UInt): ByteArray =
  ByteArray(length.toInt()).also { bytes ->
    var current = this

    (0U..<length).forEach {
      bytes[length - it - 1U] = current.toByte()
      current = current shr 8
    }
  }

infix fun UShort.shrToByte(bitCount: Int): Byte = (toInt() shr bitCount).toByte()

infix fun UInt.shrToByte(bitCount: Int): Byte = (toInt() shr bitCount).toByte()

infix fun ULong.shrToByte(bitCount: Int): Byte = (toLong() shr bitCount).toByte()

fun UInt.Companion.fromBytes(bytes: ByteArray): UInt = Int.fromBytes(bytes).toUInt()

fun Int.Companion.fromBytes(bytes: ByteArray): Int {
  var result = 0

  for (b in bytes) {
    result = result shl 8
    result += b.u
  }

  return result
}

fun ULong.Companion.fromBytes(bytes: ByteArray): ULong = Long.fromBytes(bytes).toULong()

fun Long.Companion.fromBytes(bytes: ByteArray): Long {
  var result = 0L

  for (b in bytes) {
    result = result shl 8
    result += b.u
  }

  return result
}

fun UShort.Companion.fromBytes(
  msb: Byte,
  lsb: Byte,
): UShort = Int.fromBytes(msb, lsb).toUShort()

fun UInt.Companion.fromBytes(
  msb: Byte,
  lsb: Byte,
): UInt = Int.fromBytes(msb, lsb).toUInt()

fun Int.Companion.fromBytes(
  msb: Byte,
  lsb: Byte,
): Int = (msb.u shl 8) + lsb.u

fun UInt.Companion.fromBytes(
  msb: Byte,
  b2: Byte,
  lsb: Byte,
): UInt = Int.fromBytes(msb, b2, lsb).toUInt()

fun Int.Companion.fromBytes(
  msb: Byte,
  b2: Byte,
  lsb: Byte,
): Int =
  (msb.u shl 16) +
    (b2.u shl 8) +
    lsb.u

val Byte.u: Int
  get() = toInt() and 0xFF

fun UIntRange.toIntRange(): IntRange = first.toInt()..last.toInt()

fun UIntRange.intersect(other: UIntRange): UIntRange =
  if (first > other.last || last < other.first) {
    UIntRange.EMPTY
  } else if (first > other.first) {
    first..minOf(last, other.last)
  } else {
    other.first..minOf(last, other.last)
  }

fun UIntRange.isNotEmpty(): Boolean = !isEmpty()

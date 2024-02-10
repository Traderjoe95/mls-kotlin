package de.traderjoe.ulid.internal

import arrow.core.raise.Raise
import de.traderjoe.ulid.error.ULIDError.InvalidCharacter
import kotlin.experimental.and
import kotlin.experimental.or

internal object CrockfordBase32 {
  private val ALPHABET: CharArray =
    charArrayOf(
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
      'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z',
    )
  internal val ALPHABET_SET: Set<Char> = ALPHABET.toSet()

  private val ALPHABET_INV: Map<Char, Byte> =
    mapOf(
      '0' to 0x00, '1' to 0x01, '2' to 0x02, '3' to 0x03, '4' to 0x04, '5' to 0x05, '6' to 0x06, '7' to 0x07,
      '8' to 0x08, '9' to 0x09, 'A' to 0x0A, 'B' to 0x0B, 'C' to 0x0C, 'D' to 0x0D, 'E' to 0x0E, 'F' to 0x0F,
      'G' to 0x10, 'H' to 0x11, 'J' to 0x12, 'K' to 0x13, 'M' to 0x14, 'N' to 0x15, 'P' to 0x16, 'Q' to 0x17,
      'R' to 0x18, 'S' to 0x19, 'T' to 0x1A, 'V' to 0x1B, 'W' to 0x1C, 'X' to 0x1D, 'Y' to 0x1E, 'Z' to 0x1F,
    )

  private val BIT_MASK: ByteArray =
    byteArrayOf(
      0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF.toByte(),
    )

  internal fun ByteArray.encodeBase32(): String {
    var remainingBits = 8
    var currentIdx = size - 1
    val chars =
      CharArray(
        (size * 8).let { bitCount ->
          bitCount / 5 + minOf(1, bitCount % 5)
        },
      )

    for (i in chars.size - 1 downTo 0) {
      val consumedBits = 8 - remainingBits
      val takeBits = minOf(remainingBits, 5)
      var fiveBits = (getPadded(currentIdx) and (BIT_MASK[takeBits] shl consumedBits)) shr consumedBits

      if (remainingBits <= 5) {
        currentIdx--

        if (remainingBits < 5) {
          val required = 5 - remainingBits
          val additionalBits = (getPadded(currentIdx) and BIT_MASK[required]) shl remainingBits

          fiveBits = fiveBits or additionalBits
        }

        remainingBits += 3
      } else {
        remainingBits -= 5
      }

      chars[i] = ALPHABET[fiveBits.toInt()]
    }

    return chars.concatToString()
  }

  context(Raise<InvalidCharacter>)
  internal fun String.decodeBase32(): ByteArray {
    var remainingBits = 5
    var currentIdx = length - 1
    val bytes = ByteArray((length * 5) / 8)

    for (i in bytes.size - 1 downTo 0) {
      var byte = getBits(currentIdx, remainingBits, 5 - remainingBits)
      var bits = remainingBits

      if (remainingBits <= 3) {
        currentIdx--

        byte = (byte or (getBits(currentIdx, 5, 0) shl remainingBits))
        bits += 5
      }

      currentIdx--

      if (bits < 8) {
        byte = (byte or (getBits(currentIdx, 8 - bits, 0) shl bits))
      }

      remainingBits = bits - 3

      bytes[i] = byte
    }

    return bytes
  }

  context(Raise<InvalidCharacter>)
  private fun String.getBits(
    idx: Int,
    bits: Int,
    shift: Int,
  ): Byte = ((ALPHABET_INV[this[idx]] ?: raise(InvalidCharacter(this[idx]))) and (BIT_MASK[bits] shl shift)) shr shift

  private fun ByteArray.getPadded(idx: Int): Byte = if (idx < 0) 0 else this[idx]

  private infix fun Byte.shl(bitCount: Int): Byte = ((toInt() and 0xFF) shl bitCount).toByte()

  private infix fun Byte.shr(bitCount: Int): Byte = ((toInt() and 0xFF) shr bitCount).toByte()
}

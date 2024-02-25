package com.github.traderjoe95.mls.protocol.util

import arrow.core.Nel
import com.github.traderjoe95.mls.codec.util.uSize

val Array<*>.uSize: UInt
  get() = size.toUInt()

operator fun <T> Array<T>.get(index: UInt): T = this[index.toInt()]

operator fun <T> Array<T>.set(
  index: UInt,
  value: T,
) {
  this[index.toInt()] = value
}

operator fun ByteArray.set(
  index: UInt,
  value: Byte,
) {
  this[index.toInt()] = value
}

operator fun <T> Array<T>.get(indices: Iterable<UInt>): List<T> = slice(indices.map { it.toInt() })

fun <T> Array<T>.sliceArray(indices: Iterable<UInt>): Array<T> = sliceArray(indices.map { it.toInt() })

fun ByteArray.padStart(
  paddedLength: UInt,
  value: Byte = 0,
): ByteArray =
  if (uSize >= paddedLength) {
    this
  } else {
    ByteArray(paddedLength.toInt()).also { bytes ->
      if (value.toInt() != 0) (0U..<(paddedLength - uSize)).forEach { bytes[it] = value }

      copyInto(bytes, destinationOffset = (paddedLength - uSize).toInt())
    }
  }

operator fun <T> List<T>.get(index: UInt): T = this[index.toInt()]

operator fun <T> Nel<T>.get(index: UInt): T = this[index.toInt()]

operator fun <T> Nel<T>.get(index: ULong): T = this[index.toUInt()]

fun <T> Iterable<T>.zipWithIndex(): Iterable<Pair<T, Int>> = zip(generateSequence(0, Int::inc).asIterable())

fun ByteArray.wipe() = fill(0)

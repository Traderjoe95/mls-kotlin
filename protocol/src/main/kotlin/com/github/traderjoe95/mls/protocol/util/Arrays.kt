package com.github.traderjoe95.mls.protocol.util

import arrow.core.Nel

val Array<*>.uSize: UInt
  get() = size.toUInt()

operator fun <T> Array<T>.get(index: UInt): T = this[index.toInt()]

operator fun <T> Array<T>.set(
  index: UInt,
  value: T,
) {
  this[index.toInt()] = value
}

operator fun <T> Array<T>.get(indices: Iterable<UInt>): List<T> = slice(indices.map { it.toInt() })

fun <T> Array<T>.sliceArray(indices: Iterable<UInt>): Array<T> = sliceArray(indices.map { it.toInt() })

operator fun <T> List<T>.get(index: UInt): T = this[index.toInt()]

operator fun <T> Nel<T>.get(index: UInt): T = this[index.toInt()]

operator fun <T> Nel<T>.get(index: ULong): T = this[index.toUInt()]

fun <T> Iterable<T>.zipWithIndex(): Iterable<Pair<T, Int>> = zip(generateSequence(0, Int::inc).asIterable())

fun ByteArray.wipe() = fill(0)

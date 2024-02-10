package com.github.traderjoe95.mls.protocol.util

fun log2(x: UInt): UInt =
  if (x == 0U) {
    0U
  } else {
    generateSequence(1U) { it + 1U }.dropWhile { x shr it > 0U }.first() - 1U
  }

fun log2(x: Int): Int =
  if (x == 0) {
    0
  } else {
    generateSequence(1) { it + 1 }.dropWhile { x shr it > 0 }.first() - 1
  }

infix fun UInt.shl(bitCount: UInt): UInt = this shl bitCount.toInt()

infix fun UInt.shr(bitCount: UInt): UInt = this shr bitCount.toInt()

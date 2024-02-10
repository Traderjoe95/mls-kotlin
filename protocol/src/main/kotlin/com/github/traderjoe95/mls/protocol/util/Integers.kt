package com.github.traderjoe95.mls.protocol.util

infix fun UInt.pow(exponent: UInt): UInt = (1U..exponent).fold(1U) { pow, _ -> pow * this }

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

fun pow2(x: UInt): UInt = 1U shl x
fun pow2(x: Int): Int = 1 shl x

infix fun UInt.shl(bitCount: UInt): UInt = this shl bitCount.toInt()

infix fun UInt.shr(bitCount: UInt): UInt = this shr bitCount.toInt()

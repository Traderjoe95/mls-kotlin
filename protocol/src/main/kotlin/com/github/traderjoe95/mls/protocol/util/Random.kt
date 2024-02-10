package com.github.traderjoe95.mls.protocol.util

import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.round
import kotlin.properties.Delegates

fun SecureRandom.nextBytes(size: Int): ByteArray = ByteArray(size).also(::nextBytes)

class TruncatedRoundedGaussian(private val base: SecureRandom = SecureRandom()) {
  private var nextGaussian by Delegates.notNull<Double>()
  private var hasNextGaussian: AtomicBoolean = AtomicBoolean(false)

  fun next(
    mean: UInt,
    stdDev: Double,
  ): UInt = round(nextTruncatedGaussian() * stdDev).toUInt() + mean

  private fun nextTruncatedGaussian(): Double {
    if (hasNextGaussian.compareAndSet(true, false)) {
      return nextGaussian
    } else {
      val (z1, z2) =
        generateSequence {
          val v1 = 2 * base.nextDouble() - 1
          val v2 = 2 * base.nextDouble() - 1

          Triple(v1, v2, v1 * v1 + v2 * v2)
        }.dropWhile { it.third >= 1 || it.third == 0.0 }
          .map { (v1, v2, s) ->
            val multiplier = StrictMath.sqrt(-2 * StrictMath.log(s) / s)
            (v1 * multiplier) to (v2 * multiplier)
          }
          .dropWhile { it.first < 0 || it.second < 0 }
          .first()

      nextGaussian = z2
      hasNextGaussian.set(true)

      return z1
    }
  }
}

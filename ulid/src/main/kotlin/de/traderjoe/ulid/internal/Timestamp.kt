package de.traderjoe.ulid.internal

import java.time.Instant

@JvmInline
internal value class Timestamp internal constructor(internal val epochMillis: Long) {
  internal val bytes: ByteArray
    get() =
      byteArrayOf(
        (epochMillis shr 40).toByte(),
        (epochMillis shr 32).toByte(),
        (epochMillis shr 24).toByte(),
        (epochMillis shr 16).toByte(),
        (epochMillis shr 8).toByte(),
        epochMillis.toByte(),
      )

  internal val instant: Instant
    get() = Instant.ofEpochMilli(epochMillis)

  internal companion object {
    internal fun now(): Timestamp = Timestamp(System.currentTimeMillis() and 0x0000FFFFFFFFFFFFL)

    internal fun fromBytes(byteArray: ByteArray): Timestamp =
      Timestamp(
        byteArray.fold(0L) { acc, byte ->
          (acc shl 8) or (byte.toLong() and 0xFF)
        },
      )
  }
}

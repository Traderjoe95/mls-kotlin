package de.traderjoe.ulid

import arrow.core.Either
import arrow.core.raise.either
import de.traderjoe.ulid.error.ULIDError
import de.traderjoe.ulid.error.ULIDError.BadLength
import de.traderjoe.ulid.error.ULIDError.InvalidCharacter
import de.traderjoe.ulid.error.ULIDError.Overflow
import de.traderjoe.ulid.internal.CrockfordBase32.ALPHABET_SET
import de.traderjoe.ulid.internal.CrockfordBase32.decodeBase32
import de.traderjoe.ulid.internal.CrockfordBase32.encodeBase32
import de.traderjoe.ulid.internal.Randomness
import de.traderjoe.ulid.internal.Timestamp
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Instant

class ULID internal constructor(
  internal val time: Timestamp,
  internal val randomness: Randomness,
) {
  val timestamp: Instant
    get() = time.instant

  val entropy: ByteArray
    get() = randomness.bytes.copyOf()

  override fun toString(): String = toBytes().encodeBase32()

  fun toBytes(): ByteArray = time.bytes + randomness.bytes

  internal operator fun component1(): Timestamp = time

  internal operator fun component2(): Randomness = randomness

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as ULID

    if (time.epochMillis != other.time.epochMillis) return false

    return randomness.bytes.contentEquals(other.randomness.bytes)
  }

  override fun hashCode(): Int {
    var result = time.epochMillis.hashCode()
    result = 31 * result + randomness.bytes.contentHashCode()
    return result
  }

  companion object {
    const val MIN_STR = "00000000000000000000000000"
    const val MAX_STR = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"

    val MIN = ULID(Timestamp(0L), Randomness(ByteArray(10)))
    val MAX = ULID(Timestamp(0xFFFFFFFFFFFFL), Randomness(ByteArray(10) { 0xFF.toByte() }))

    private val mutex: Mutex = Mutex()
    private var last: ULID? = null

    internal suspend fun next(): ULID =
      mutex.withLock {
        when (val l = last) {
          null -> ULID(Timestamp.now(), Randomness.random())
          else ->
            l.let { (time, randomness) ->
              Timestamp.now().let { now ->
                if (time == now) {
                  ULID(time, randomness.increment())
                } else {
                  ULID(now, Randomness.random())
                }
              }
            }
        }.also { last = it }
      }

    fun String.toULID(): Either<ULIDError, ULID> = fromString(this)

    fun fromString(ulid: String): Either<ULIDError, ULID> =
      either {
        when {
          ulid.length != 26 -> raise(BadLength(ulid.length.toUInt(), 26U))
          ulid.any { it !in ALPHABET_SET } -> raise(InvalidCharacter(ulid.first { it !in ALPHABET_SET }))
          ulid > MAX_STR -> raise(Overflow)
          else -> ulid.decodeBase32().let(::fromBytes).bind()
        }
      }

    fun ByteArray.toULID(): Either<BadLength, ULID> = fromBytes(this)

    fun fromBytes(ulidBytes: ByteArray): Either<BadLength, ULID> =
      either {
        when {
          ulidBytes.size != 16 -> raise(BadLength(ulidBytes.size.toUInt(), 16U))
          else ->
            ULID(
              Timestamp.fromBytes(ulidBytes.sliceArray(0..<6)),
              Randomness.fromBytes(ulidBytes.sliceArray(6..<16)),
            )
        }
      }
  }
}

package de.traderjoe.ulid

import de.traderjoe.ulid.internal.CrockfordBase32
import de.traderjoe.ulid.internal.Randomness
import de.traderjoe.ulid.internal.Timestamp
import io.kotest.property.Arb
import io.kotest.property.Gen
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.InstantRange
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.of

fun Arb.Companion.ulidStr(
  timestampRange: InstantRange,
  randomnessContent: Arb<Byte> = byte(),
): Arb<String> = ulid(timestampRange, randomnessContent).map(ULID::toString)

fun Arb.Companion.ulidStr(
  timestampRange: LongRange = 0x0L..0xFFFFFFFFFFFFL,
  randomnessContent: Arb<Byte> = byte(),
): Arb<String> = ulid(timestampRange, randomnessContent).map(ULID::toString)

fun Arb.Companion.ulidBytes(
  timestampRange: InstantRange,
  randomnessContent: Arb<Byte> = byte(),
): Arb<ByteArray> = ulid(timestampRange, randomnessContent).map(ULID::toBytes)

fun Arb.Companion.ulidBytes(
  timestampRange: LongRange = 0x0L..0xFFFFFFFFFFFFL,
  randomnessContent: Arb<Byte> = byte(),
): Arb<ByteArray> = ulid(timestampRange, randomnessContent).map(ULID::toBytes)

fun Arb.Companion.ulid(
  timestampRange: InstantRange,
  randomnessContent: Arb<Byte> = byte(),
): Arb<ULID> =
  ulid(
    timestampRange.start.toEpochMilli()..timestampRange.endInclusive.toEpochMilli(),
    randomnessContent,
  )

fun Arb.Companion.ulid(
  timestampRange: LongRange = 0x0L..0xFFFFFFFFFFFFL,
  randomnessContent: Arb<Byte> = byte(),
): Arb<ULID> =
  bind(
    timestamp(timestampRange),
    randomness(content = randomnessContent),
    ::ULID,
  )

internal fun Arb.Companion.timestamp(range: LongRange = 0x0L..0xFFFFFFFFFFFFL): Arb<Timestamp> = long(range).map(::Timestamp)

internal fun Arb.Companion.randomness(
  size: Gen<Int> = constant(10),
  content: Arb<Byte> = byte(),
): Arb<Randomness> = byteArray(size, content).map(::Randomness)

fun Codepoint.Companion.crockfordBase32(): Arb<Codepoint> =
  Arb.of(
    *CrockfordBase32.ALPHABET_SET.toTypedArray(),
  ).map(Char::code).map(::Codepoint)

package de.traderjoe.ulid.suspending

import de.traderjoe.ulid.ULID
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.inspectors.forAll
import io.kotest.matchers.date.shouldNotBeAfter
import io.kotest.matchers.date.shouldNotBeBefore
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import java.time.Instant
import java.time.temporal.ChronoUnit

class ULIDSuspendingTest : ShouldSpec({
  context("ULID.new()") {
    should("return a distinct result on each call") {
      val before = Instant.now().truncatedTo(ChronoUnit.MILLIS)
      val results = mutableListOf<ULID>()

      for (i in 0..<10_000) {
        results.add(ULID.new())
      }
      val after = Instant.now().truncatedTo(ChronoUnit.MILLIS)

      results.size shouldBe results.toSet().size

      results.forAll {
        it.time.epochMillis shouldBeGreaterThanOrEqual before.toEpochMilli()
        it.time.epochMillis shouldBeLessThanOrEqual after.toEpochMilli()

        it.time.instant shouldNotBeBefore before
        it.time.instant shouldNotBeAfter after

        it.timestamp shouldBe it.time.instant
      }

      results.groupBy { it.time.epochMillis }.forEach { (_, group) ->
        group.zipWithNext().forAll { (prev, next) ->
          for (i in 9 downTo 0) {
            if ((prev.randomness.bytes[i].toInt() and 0xFF) < 0xFF) {
              next.randomness.bytes[i] shouldBe (prev.randomness.bytes[i] + 1).toByte()
              break
            } else {
              next.randomness.bytes[i] shouldBe 0
            }
          }
        }
      }
    }
  }

  context("ULID.newString()") {
    should("return a distinct result on each call") {
      val before = Instant.now().truncatedTo(ChronoUnit.MILLIS)
      val results = mutableListOf<String>()

      for (i in 0..<10_000) {
        results.add(ULID.newString())
      }
      val after = Instant.now().truncatedTo(ChronoUnit.MILLIS)

      results.size shouldBe results.toSet().size

      results.forAll { str ->
        ULID.fromString(str).shouldBeRight().also {
          it.time.epochMillis shouldBeGreaterThanOrEqual before.toEpochMilli()
          it.time.epochMillis shouldBeLessThanOrEqual after.toEpochMilli()

          it.time.instant shouldNotBeBefore before
          it.time.instant shouldNotBeAfter after

          it.timestamp shouldBe it.time.instant
        }
      }

      results.map { ULID.fromString(it).shouldBeRight() }.groupBy { it.time.epochMillis }.forEach { (_, group) ->
        group.zipWithNext().forAll { (prev, next) ->
          for (i in 9 downTo 0) {
            if ((prev.randomness.bytes[i].toInt() and 0xFF) < 0xFF) {
              next.randomness.bytes[i] shouldBe (prev.randomness.bytes[i] + 1).toByte()
              break
            } else {
              next.randomness.bytes[i] shouldBe 0
            }
          }
        }
      }
    }
  }

  context("ULID.newBinary()") {
    should("return a distinct result on each call") {
      val before = Instant.now().truncatedTo(ChronoUnit.MILLIS)
      val results = mutableListOf<ByteArray>()

      for (i in 0..<10_000) {
        results.add(ULID.newBinary())
      }
      val after = Instant.now().truncatedTo(ChronoUnit.MILLIS)

      results.size shouldBe results.toSet().size

      results.forAll { bytes ->
        ULID.fromBytes(bytes).shouldBeRight().also {
          it.time.epochMillis shouldBeGreaterThanOrEqual before.toEpochMilli()
          it.time.epochMillis shouldBeLessThanOrEqual after.toEpochMilli()

          it.time.instant shouldNotBeBefore before
          it.time.instant shouldNotBeAfter after

          it.timestamp shouldBe it.time.instant
        }
      }

      results.map { ULID.fromBytes(it).shouldBeRight() }.groupBy { it.time.epochMillis }.forEach { (_, group) ->
        group.zipWithNext().forAll { (prev, next) ->
          for (i in 9 downTo 0) {
            if ((prev.randomness.bytes[i].toInt() and 0xFF) < 0xFF) {
              next.randomness.bytes[i] shouldBe (prev.randomness.bytes[i] + 1).toByte()
              break
            } else {
              next.randomness.bytes[i] shouldBe 0
            }
          }
        }
      }
    }
  }
})

package de.traderjoe.ulid

import arrow.core.raise.either
import de.traderjoe.ulid.error.ULIDError.BadLength
import de.traderjoe.ulid.error.ULIDError.InvalidCharacter
import de.traderjoe.ulid.error.ULIDError.Overflow
import de.traderjoe.ulid.internal.CrockfordBase32
import de.traderjoe.ulid.internal.CrockfordBase32.decodeBase32
import de.traderjoe.ulid.internal.CrockfordBase32.encodeBase32
import de.traderjoe.ulid.internal.Randomness
import de.traderjoe.ulid.internal.Timestamp
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldNotBeSameInstanceAs
import io.kotest.property.Arb
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.printableAscii
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll

class ULIDTest : ShouldSpec({
  context("ULID.fromString(ulid)") {
    should("return the ULID if the string represents a valid ULID") {
      checkAll(Arb.string(26, Codepoint.crockfordBase32()).filter { it <= ULID.MAX_STR }) { ulidStr ->
        ULID.fromString(ulidStr).shouldBeRight().also {
          it.toString() shouldBe ulidStr
          it.toBytes() shouldBe either { ulidStr.decodeBase32() }.shouldBeRight()

          it.time.bytes shouldBe either { ulidStr.slice(0..<10).decodeBase32() }.shouldBeRight()
          it.randomness.bytes shouldBe either { ulidStr.slice(10..<26).decodeBase32() }.shouldBeRight()
        }
      }
    }

    should("return an error if the string is shorter than 26 characters") {
      checkAll(Arb.string(0..25, Codepoint.crockfordBase32())) {
        ULID.fromString(it) shouldBeLeft BadLength(it.length.toUInt(), 26U)
      }
    }

    should("return an error if the string is longer than 26 characters") {
      checkAll(Arb.string(27..256, Codepoint.crockfordBase32())) {
        ULID.fromString(it) shouldBeLeft BadLength(it.length.toUInt(), 26U)
      }
    }

    should("return an error if the ULID is larger than ULID.MAX") {
      checkAll(Arb.string(26, Codepoint.crockfordBase32()).filter { it > ULID.MAX_STR }) {
        ULID.fromString(it) shouldBeLeft Overflow
      }
    }

    should("return an error if the string contains any invalid characters with respect to Crockford's Base 32") {
      checkAll(
        Arb.string(
          26,
          Arb.choice(
            Codepoint.crockfordBase32(),
            Codepoint.printableAscii(),
          ),
        ).filter {
          it.any { ch -> ch !in CrockfordBase32.ALPHABET_SET }
        },
      ) { str ->
        ULID.fromString(str) shouldBeLeft
          InvalidCharacter(
            str.first { it !in CrockfordBase32.ALPHABET_SET },
          )
      }
    }
  }

  context("ULID.fromBytes(bytes)") {
    should("return the ULID if the byte array has exactly 16 bytes") {
      checkAll(Arb.byteArray(Arb.constant(16), Arb.byte())) { ulidBytes ->
        ULID.fromBytes(ulidBytes).shouldBeRight().also {
          it.toBytes() shouldBe ulidBytes
          it.toString() shouldBe ulidBytes.encodeBase32()

          it.entropy shouldBe ulidBytes.sliceArray(6..<16)
          it.entropy shouldNotBeSameInstanceAs it.randomness.bytes

          it.time.bytes shouldBe ulidBytes.sliceArray(0..<6)
          it.randomness.bytes shouldBe ulidBytes.sliceArray(6..<16)
        }
      }
    }

    should("return an error if the array is shorter than 16 bytes") {
      checkAll(Arb.byteArray(Arb.int(0..15), Arb.byte())) {
        ULID.fromBytes(it) shouldBeLeft BadLength(it.size.toUInt(), 16U)
      }
    }

    should("return an error if the array is longer than 16 bytes") {
      checkAll(Arb.byteArray(Arb.int(17..256), Arb.byte())) {
        ULID.fromBytes(it) shouldBeLeft BadLength(it.size.toUInt(), 16U)
      }
    }
  }

  context("ULID.MIN") {
    should("be equivalent to 00000000000000000000000000") {
      ULID.MIN.apply {
        toString() shouldBe "00000000000000000000000000"
        toString() shouldBe ULID.MIN_STR
        time.epochMillis shouldBe 0L
        randomness.bytes shouldBe ByteArray(10) { 0 }
      }
    }
  }

  context("ULID.MAX") {
    should("be equivalent to 7ZZZZZZZZZZZZZZZZZZZZZZZZZ") {
      ULID.MAX.apply {
        toString() shouldBe "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
        toString() shouldBe ULID.MAX_STR
        time.epochMillis shouldBe 0xFFFFFFFFFFFFL
        randomness.bytes shouldBe ByteArray(10) { 0xFF.toByte() }
      }
    }
  }

  context("ULID.equals(other)") {
    should("return true if both operands are the same instance") {
      checkAll(Arb.ulid()) { ulid ->
        (ulid == ulid).shouldBeTrue()
      }
    }

    should("return true if both operands have the same value, even if they're not the same instance") {
      checkAll(Arb.ulid()) { ulid ->
        val copy =
          ULID(
            Timestamp(ulid.time.epochMillis),
            Randomness(ulid.entropy),
          )

        (ulid == copy).shouldBeTrue()
      }
    }

    should("return false if both operands have the different values") {
      checkAll(
        Arb.pair(Arb.ulid(), Arb.ulid()).filter { (ulidA, ulidB) ->
          ulidA.time.epochMillis != ulidB.time.epochMillis || ulidA.entropy.contentEquals(ulidB.entropy).not()
        },
      ) { (ulidA, ulidB) ->
        (ulidA == ulidB).shouldBeFalse()
      }
    }

    should("return false if the left operand is not a ULID") {
      checkAll(Arb.ulid()) { ulid ->
        ulid.equals(1).shouldBeFalse()
        ulid.equals(null).shouldBeFalse()
        ulid.equals(ulid.toString()).shouldBeFalse()
      }
    }
  }

  context("ULID.hashCode()") {
    should("return the same if both receivers are the same instance") {
      checkAll(Arb.ulid()) { ulid ->
        ulid.hashCode() shouldBe ulid.hashCode()
      }
    }

    should("return the same if both receivers have the same value, even if they're not the same instance") {
      checkAll(Arb.ulid()) { ulid ->
        val copy =
          ULID(
            Timestamp(ulid.time.epochMillis),
            Randomness(ulid.entropy),
          )

        ulid.hashCode() shouldBe copy.hashCode()
      }
    }

    should("return false if both receivers have the different values") {
      checkAll(
        Arb.pair(Arb.ulid(), Arb.ulid()).filter { (ulidA, ulidB) ->
          ulidA.time.epochMillis != ulidB.time.epochMillis || ulidA.entropy.contentEquals(ulidB.entropy).not()
        },
      ) { (ulidA, ulidB) ->
        ulidA.hashCode() shouldNotBe ulidB.hashCode()
      }
    }
  }
})

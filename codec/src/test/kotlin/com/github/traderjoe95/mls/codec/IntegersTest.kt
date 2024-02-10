package com.github.traderjoe95.mls.codec

import com.github.traderjoe95.mls.codec.error.IntegerError
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.uByte
import io.kotest.property.arbitrary.uInt
import io.kotest.property.arbitrary.uLong
import io.kotest.property.arbitrary.uShort
import io.kotest.property.checkAll

class IntegersTest : ShouldSpec({
  context("UInt8") {
    context("encode") {
      should("return a the single byte representing the UByte") {
        checkAll(Arb.uByte()) {
          UInt8(it).encode() shouldBe byteArrayOf(it.toByte())
        }
      }
    }

    context("toByte()") {
      should("return the corresponding signed byte value") {
        checkAll(Arb.uByte()) {
          UInt8(it).toByte() shouldBe it.toByte()
        }
      }
    }

    context("toInt()") {
      should("return the Int representing the same numeric value") {
        checkAll(Arb.uByte()) {
          UInt8(it).toInt() shouldBe it.toUInt().toInt()
        }
      }
    }

    context("toLong()") {
      should("return the Long representing the same numeric value") {
        checkAll(Arb.uByte()) {
          UInt8(it).toLong() shouldBe it.toULong().toLong()
        }
      }
    }
  }

  context("UInt16") {
    context("encode") {
      should("return the two bytes representing the UShort") {
        checkAll(Arb.uShort()) {
          UInt16(it).encode() shouldBe byteArrayOf((it.toInt() shr 8).toByte(), it.toByte())
        }
      }
    }

    context("toByte()") {
      should("return the least significant byte") {
        checkAll(Arb.uShort()) {
          UInt16(it).toByte() shouldBe it.toByte()
        }
      }
    }

    context("shrToByte bitCount") {
      should("return the least significant byte of the number shifted right by bitCount bits") {
        checkAll(Arb.uShort(), Arb.int(0..64)) { value, bitCount ->
          UInt16(value) shrToByte bitCount shouldBe (value.toInt() shr bitCount).toByte()
        }
      }
    }

    context("toInt()") {
      should("return the Int representing the same numeric value") {
        checkAll(Arb.uShort()) {
          UInt16(it).toInt() shouldBe it.toUInt().toInt()
        }
      }
    }

    context("toLong()") {
      should("return the Long representing the same numeric value") {
        checkAll(Arb.uShort()) {
          UInt16(it).toLong() shouldBe it.toULong().toLong()
        }
      }
    }
  }

  context("UInt24") {
    context("encode") {
      should("return the three bytes representing the lower three bytes of the UInt") {
        checkAll(Arb.uInt(max = 0xFFFFFFU)) {
          shouldNotRaise { UInt24.of(it) }.encode() shouldBe
            byteArrayOf(
              (it.toInt() shr 16).toByte(),
              (it.toInt() shr 8).toByte(),
              it.toByte(),
            )
        }
      }
    }

    context("toByte()") {
      should("return the least significant byte") {
        checkAll(Arb.uInt(max = 0xFFFFFFU)) {
          shouldNotRaise { UInt24.of(it) }.toByte() shouldBe it.toByte()
        }
      }
    }

    context("shrToByte bitCount") {
      should("return the least significant byte of the number shifted right by bitCount bits") {
        checkAll(Arb.uInt(max = 0xFFFFFFU), Arb.int(0..64)) { value, bitCount ->
          shouldNotRaise { UInt24.of(value) } shrToByte bitCount shouldBe (value.toInt() shr bitCount).toByte()
        }
      }
    }

    context("toInt()") {
      should("return the Int representing the same numeric value") {
        checkAll(Arb.uInt(max = 0xFFFFFFU)) {
          shouldNotRaise { UInt24.of(it) }.toInt() shouldBe it.toInt()
        }
      }
    }

    context("toLong()") {
      should("return the Long representing the same numeric value") {
        checkAll(Arb.uInt(max = 0xFFFFFFU)) {
          shouldNotRaise { UInt24.of(it) }.toLong() shouldBe it.toULong().toLong()
        }
      }
    }

    context("of(value)") {
      should("raise an error if the number can't be represented with three bytes") {
        checkAll(Arb.uInt(min = 0x1000000U)) {
          shouldRaise<IntegerError.ValueTooBig> { UInt24.of(it) } shouldBe IntegerError.ValueTooBig("uint24", it)
        }
      }
    }
  }

  context("UInt32") {
    context("encode") {
      should("return the four bytes representing the UInt") {
        checkAll(Arb.uInt()) {
          UInt32(it).encode() shouldBe
            byteArrayOf(
              (it.toInt() shr 24).toByte(),
              (it.toInt() shr 16).toByte(),
              (it.toInt() shr 8).toByte(),
              it.toByte(),
            )
        }
      }
    }

    context("toByte()") {
      should("return the least significant byte") {
        checkAll(Arb.uInt()) {
          UInt32(it).toByte() shouldBe it.toByte()
        }
      }
    }

    context("shrToByte bitCount") {
      should("return the least significant byte of the number shifted right by bitCount bits") {
        checkAll(Arb.uInt(), Arb.int(0..64)) { value, bitCount ->
          UInt32(value) shrToByte bitCount shouldBe (value.toInt() shr bitCount).toByte()
        }
      }
    }

    context("toInt()") {
      should("return the Int representing the same binary value") {
        checkAll(Arb.uInt()) {
          UInt32(it).toInt() shouldBe it.toInt()
        }
      }
    }

    context("toLong()") {
      should("return the Long representing the same numeric value") {
        checkAll(Arb.uInt()) {
          UInt32(it).toLong() shouldBe it.toULong().toLong()
        }
      }
    }
  }

  context("UInt64") {
    context("encode") {
      should("return the eight bytes representing the ULong") {
        checkAll(Arb.uLong()) {
          UInt64(it).encode() shouldBe
            byteArrayOf(
              (it.toLong() shr 56).toByte(),
              (it.toLong() shr 48).toByte(),
              (it.toLong() shr 40).toByte(),
              (it.toLong() shr 32).toByte(),
              (it.toLong() shr 24).toByte(),
              (it.toLong() shr 16).toByte(),
              (it.toLong() shr 8).toByte(),
              it.toByte(),
            )
        }
      }
    }

    context("toByte()") {
      should("return the least significant byte") {
        checkAll(Arb.uLong()) {
          UInt64(it).toByte() shouldBe it.toByte()
        }
      }
    }

    context("shrToByte bitCount") {
      should("return the least significant byte of the number shifted right by bitCount bits") {
        checkAll(Arb.uLong(), Arb.int(0..64)) { value, bitCount ->
          UInt64(value) shrToByte bitCount shouldBe (value.toLong() shr bitCount).toByte()
        }
      }
    }

    context("toInt()") {
      should("return the Int representing the lower 4 bytes of the binary value") {
        checkAll(Arb.uLong()) {
          UInt64(it).toInt() shouldBe it.toInt()
        }
      }
    }

    context("toLong()") {
      should("return the Long representing the same binary value") {
        checkAll(Arb.uLong()) {
          UInt64(it).toLong() shouldBe it.toLong()
        }
      }
    }
  }
})

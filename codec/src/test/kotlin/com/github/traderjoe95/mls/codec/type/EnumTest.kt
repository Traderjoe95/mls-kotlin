package com.github.traderjoe95.mls.codec.type

import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.EnumError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.util.shrToByte
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.enum
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll

class EnumTest : ShouldSpec({
  context("EnumT") {
    val enum1Byte = shouldNotRaise { enum<TestEnum1B>() }
    val enum2Byte = shouldNotRaise { enum<TestEnum2B>() }
    val enum3Byte = shouldNotRaise { enum<TestEnum3B>() }
    val enum4Byte = shouldNotRaise { enum<TestEnum4B>() }

    context("when encoding") {
      should("use one byte to encode the ordinal if the maximum ordinal is in 0..0xFF") {
        checkAll(Arb.enum<TestEnum1B>()) {
          shouldNotRaise { enum1Byte.encode(it) } shouldBe byteArrayOf(it.ord.first.toByte())
        }
      }

      should("use two bytes to encode the ordinal if the maximum ordinal is in 0x100..0xFFFF") {
        checkAll(Arb.enum<TestEnum2B>().filter { it.isValid }) {
          shouldNotRaise { enum2Byte.encode(it) } shouldBe
            byteArrayOf(
              it.ord.first shrToByte 8,
              it.ord.first.toByte(),
            )
        }
      }

      should("use three bytes to encode the ordinal if the maximum ordinal is in 0x10000..0xFFFFFF") {
        checkAll(Arb.enum<TestEnum3B>().filter { it.isValid }) {
          shouldNotRaise { enum3Byte.encode(it) } shouldBe
            byteArrayOf(
              it.ord.first shrToByte 16,
              it.ord.first shrToByte 8,
              it.ord.first.toByte(),
            )
        }
      }

      should("use four bytes to encode the ordinal if the maximum ordinal is in 0x1000000..0xFFFFFFFF") {
        checkAll(Arb.enum<TestEnum4B>()) {
          shouldNotRaise { enum4Byte.encode(it) } shouldBe
            byteArrayOf(
              it.ord.first shrToByte 24,
              it.ord.first shrToByte 16,
              it.ord.first shrToByte 8,
              it.ord.first.toByte(),
            )
        }
      }

      should("raise an error if the enum constant has isValid = false") {
        shouldRaise<EncoderError.InvalidEnumValue> {
          enum2Byte.encode(TestEnum2B.UPPER_)
        } shouldBe EncoderError.InvalidEnumValue("TestEnum2B", "UPPER_")

        shouldRaise<EncoderError.InvalidEnumValue> {
          enum3Byte.encode(TestEnum3B.UPPER_)
        } shouldBe EncoderError.InvalidEnumValue("TestEnum3B", "UPPER_")
      }
    }

    context("when decoding") {
      should("consume one byte if the maximum ord value is in 0..0xFF and map it to the right enum constant") {
        checkAll(
          Arb.enum<TestEnum1B>().flatMap { enum ->
            // Take any ord from the enum constant's range
            Arb.uInt(enum.ord).flatMap { ord ->
              Arb.slice(
                byteArrayOf(ord.toByte()),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to enum }
            }
          },
        ) { (slice, enum) ->
          shouldNotRaise { enum1Byte.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 1U
            remaining.firstIndex shouldBe slice.firstIndex + 1U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 1U)

            decoded shouldBe enum
          }
        }
      }

      should("consume two bytes if the maximum ord value is in 0x100..0xFFFF and map it to the right enum constant") {
        checkAll(
          Arb.enum<TestEnum2B>().filter { it.isValid }.flatMap { enum ->
            // Take any ord from the enum constant's range
            Arb.uInt(enum.ord).flatMap { ord ->
              Arb.slice(
                byteArrayOf(
                  ord shrToByte 8,
                  ord.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to enum }
            }
          },
        ) { (slice, enum) ->
          shouldNotRaise { enum2Byte.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 2U
            remaining.firstIndex shouldBe slice.firstIndex + 2U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 2U)

            decoded shouldBe enum
          }
        }
      }

      should("consume three bytes if the maximum ord value is in 0x10000..0xFFFFFF and map it to the right enum constant") {
        checkAll(
          Arb.enum<TestEnum3B>().filter { it.isValid }.flatMap { enum ->
            // Take any ord from the enum constant's range
            Arb.uInt(enum.ord).flatMap { ord ->
              Arb.slice(
                byteArrayOf(
                  ord shrToByte 16,
                  ord shrToByte 8,
                  ord.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to enum }
            }
          },
        ) { (slice, enum) ->
          shouldNotRaise { enum3Byte.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 3U
            remaining.firstIndex shouldBe slice.firstIndex + 3U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 3U)

            decoded shouldBe enum
          }
        }
      }

      should("consume four bytes if the maximum ord value is in 0x1000000..0xFFFFFFFF and map it to the right enum constant") {
        checkAll(
          Arb.enum<TestEnum4B>().flatMap { enum ->
            // Take any ord from the enum constant's range
            Arb.uInt(enum.ord).flatMap { ord ->
              Arb.slice(
                byteArrayOf(
                  ord shrToByte 24,
                  ord shrToByte 16,
                  ord shrToByte 8,
                  ord.toByte(),
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to enum }
            }
          },
        ) { (slice, enum) ->
          shouldNotRaise { enum4Byte.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 4U
            remaining.firstIndex shouldBe slice.firstIndex + 4U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 4U)

            decoded shouldBe enum
          }
        }
      }

      should("raise an error if the ord corresponds to an invalid enum constant") {
        val ord1 = 32000U
        checkAll(
          Arb.slice(
            byteArrayOf(
              ord1 shrToByte 8,
              ord1.toByte(),
            ),
            alreadyConsumedLength = 0U..128U,
            extraLength = 0U..128U,
          ),
        ) {
          shouldRaise<DecoderError.InvalidEnumValue> {
            enum2Byte.decode(it)
          } shouldBe DecoderError.InvalidEnumValue(it.firstIndex, "TestEnum2B", "UPPER_")
        }

        val ord2 = 0x10000U
        checkAll(
          Arb.slice(
            byteArrayOf(
              ord2 shrToByte 16,
              ord2 shrToByte 8,
              ord2.toByte(),
            ),
            alreadyConsumedLength = 0U..128U,
            extraLength = 0U..128U,
          ),
        ) {
          shouldRaise<DecoderError.InvalidEnumValue> {
            enum3Byte.decode(it)
          } shouldBe DecoderError.InvalidEnumValue(it.firstIndex, "TestEnum3B", "UPPER_")
        }
      }

      should("raise an error if the ord does not match any known enum constant") {
        checkAll(
          Arb.uInt(0U..0xFFU).filter { i ->
            TestEnum1B.entries.none { i in it.ord }
          }.flatMap { ord ->
            Arb.slice(
              byteArrayOf(ord.toByte()),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to ord }
          },
        ) { (slice, ord) ->
          shouldRaise<DecoderError.UnknownEnumValue> {
            enum1Byte.decode(slice)
          } shouldBe DecoderError.UnknownEnumValue(slice.firstIndex, "TestEnum1B", ord)
        }

        checkAll(
          Arb.uInt(0U..0xFFFFU).filter { i ->
            TestEnum2B.entries.none { i in it.ord }
          }.flatMap { ord ->
            Arb.slice(
              byteArrayOf(
                ord shrToByte 8,
                ord.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to ord }
          },
        ) { (slice, ord) ->
          shouldRaise<DecoderError.UnknownEnumValue> {
            enum2Byte.decode(slice)
          } shouldBe DecoderError.UnknownEnumValue(slice.firstIndex, "TestEnum2B", ord)
        }

        checkAll(
          Arb.uInt(0U..0xFFFFFFU).filter { i ->
            TestEnum3B.entries.none { i in it.ord }
          }.flatMap { ord ->
            Arb.slice(
              byteArrayOf(
                ord shrToByte 16,
                ord shrToByte 8,
                ord.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to ord }
          },
        ) { (slice, ord) ->
          shouldRaise<DecoderError.UnknownEnumValue> {
            enum3Byte.decode(slice)
          } shouldBe DecoderError.UnknownEnumValue(slice.firstIndex, "TestEnum3B", ord)
        }

        checkAll(
          Arb.uInt(0U..0xFFFFFFFFU).filter { i ->
            TestEnum4B.entries.none { i in it.ord }
          }.flatMap { ord ->
            Arb.slice(
              byteArrayOf(
                ord shrToByte 24,
                ord shrToByte 16,
                ord shrToByte 8,
                ord.toByte(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to ord }
          },
        ) { (slice, ord) ->
          shouldRaise<DecoderError.UnknownEnumValue> {
            enum4Byte.decode(slice)
          } shouldBe DecoderError.UnknownEnumValue(slice.firstIndex, "TestEnum4B", ord)
        }
      }

      should("raise an error if there is less than one byte remaining and the maximum ord value is in 0..0xFF") {
        checkAll(
          Arb.slice(
            byteArrayOf(),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            enum1Byte.decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)
        }
      }

      should("raise an error if there are less than two bytes remaining and the maximum ord value is in 0x100..0xFFFF") {
        checkAll(
          Arb.slice(
            Arb.byteArray(0..1),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            enum2Byte.decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 2U, slice.size)
        }
      }

      should("raise an error if there are less than three bytes remaining and the maximum ord value is in 0x10000..0xFFFFFF") {
        checkAll(
          Arb.slice(
            Arb.byteArray(0..2),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            enum3Byte.decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 3U, slice.size)
        }
      }

      should("raise an error if there are less than four bytes remaining and the maximum ord value is in 0x1000000..0xFFFFFFFF") {
        checkAll(
          Arb.slice(
            Arb.byteArray(0..3),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            enum4Byte.decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 4U, slice.size)
        }
      }
    }

    context(".create<V>") {
      should("raise an error when any ord ranges overlap") {
        shouldRaise<EnumError.AmbiguousOrd> {
          enum<TestEnumAmbiguous>()
        } shouldBe
          EnumError.AmbiguousOrd(
            "TestEnumAmbiguous",
            mapOf(
              "A" to setOf("B"),
              "B" to setOf("A", "D"),
              "D" to setOf("B", "E"),
              "E" to setOf("D"),
            ),
          )
      }

      should("raise an error when an enum constant has an empty ord range") {
        shouldRaise<EnumError.UndefinedOrd> {
          enum<TestEnumUndefined>()
        } shouldBe EnumError.UndefinedOrd("TestEnumUndefined", setOf("B"))
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength depending on the maximum ordinal") {
        enum1Byte.encodedLength shouldBe 1U
        enum2Byte.encodedLength shouldBe 2U
        enum3Byte.encodedLength shouldBe 3U
        enum4Byte.encodedLength shouldBe 4U
      }

      should("have a name of <class name>") {
        enum1Byte.name shouldBe "TestEnum1B"
        enum2Byte.name shouldBe "TestEnum2B"
        enum3Byte.name shouldBe "TestEnum3B"
        enum4Byte.name shouldBe "TestEnum4B"
      }
    }
  }
})

enum class TestEnum1B(override val ord: UIntRange, override val isValid: Boolean = true) : ProtocolEnum<TestEnum1B> {
  A(1U),
  B(2U..10U),
  C(11U..30U),
  ;

  constructor(ord: UInt, isValid: Boolean = true) : this(ord..ord, isValid)
}

enum class TestEnum2B(override val ord: UIntRange, override val isValid: Boolean = true) : ProtocolEnum<TestEnum2B> {
  A(1U),
  B(2U..10U),
  C(11U..30U),
  UPPER_(32000U, isValid = false),
  ;

  constructor(ord: UInt, isValid: Boolean = true) : this(ord..ord, isValid)
}

enum class TestEnum3B(override val ord: UIntRange, override val isValid: Boolean = true) : ProtocolEnum<TestEnum3B> {
  A(1U),
  B(2U..10U),
  C(11U..30U),
  UPPER_(0x10000U, isValid = false),
  ;

  constructor(ord: UInt, isValid: Boolean = true) : this(ord..ord, isValid)
}

enum class TestEnum4B(override val ord: UIntRange, override val isValid: Boolean = true) : ProtocolEnum<TestEnum4B> {
  A(1U),
  B(2U..10U),
  C(11U..30U),
  D(0x10000U..0x1000000U),
  ;

  constructor(ord: UInt, isValid: Boolean = true) : this(ord..ord, isValid)
}

enum class TestEnumAmbiguous(override val ord: UIntRange, override val isValid: Boolean = true) : ProtocolEnum<TestEnumAmbiguous> {
  A(0U..2U),
  B(1U..10U),
  C(20U..21U),
  D(9U..19U),
  E(12U..14U),
}

enum class TestEnumUndefined(override val ord: UIntRange, override val isValid: Boolean = true) : ProtocolEnum<TestEnumUndefined> {
  A(0U..2U),
  B(UIntRange.EMPTY),
}

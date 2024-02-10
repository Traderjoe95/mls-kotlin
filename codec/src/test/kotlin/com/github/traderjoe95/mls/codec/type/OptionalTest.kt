package com.github.traderjoe95.mls.codec.type

import arrow.core.None
import arrow.core.Option
import arrow.core.some
import com.github.traderjoe95.mls.codec.Struct2
import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.struct
import com.github.traderjoe95.mls.codec.type.struct.Struct1T
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.uInt32
import com.github.traderjoe95.mls.codec.uInt8
import com.github.traderjoe95.mls.codec.util.throwAnyError
import com.github.traderjoe95.mls.codec.vector
import io.kotest.assertions.arrow.core.shouldBeNone
import io.kotest.assertions.arrow.core.shouldBeSome
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.checkAll

class OptionalTest : ShouldSpec({
  context("optional<T>") {
    val struct =
      throwAnyError {
        struct("Test") {
          it.field("uint", uint8)
            .field("uintV", uint32[16U])
        }
      }

    val optUInt8 = optional[uint8]
    val optUInt32 = optional[uint32]
    val optStruct = optional[struct]
    val optUInt32V = throwAnyError { optional[uint32[16U]] }

    context("when encoding") {
      should("encode None as a single 0 byte") {
        for (dt in listOf(optUInt8, optUInt32, optStruct, optUInt32V)) {
          shouldNotRaise {
            @Suppress("UNCHECKED_CAST")
            (dt as DataType<Option<*>>).encode(None)
          } shouldBe byteArrayOf(0)
        }
      }

      should("encode Some(value) as a single 1 byte followed by the encoding of the value") {
        checkAll(
          Arb.uInt8(),
          Arb.vector(Arb.uInt32(), 4U),
        ) { uint, uintV ->
          shouldNotRaise { optUInt8.encode(uint.some()) } shouldBe byteArrayOf(1, uint.toByte())
          shouldNotRaise {
            optUInt32.encode(uintV.first().some())
          } shouldBe byteArrayOf(1, *uintV.first().encode())

          shouldNotRaise {
            optStruct.encode(Struct2(uint, uintV).some()) shouldBe
              byteArrayOf(
                1,
                uint.toByte(),
                *uintV.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
              )
          }

          shouldNotRaise { optUInt32V.encode(uintV.some()) } shouldBe
            byteArrayOf(
              1,
              *uintV.fold(byteArrayOf()) { b, v -> b + v.encode() },
            )
        }
      }
    }

    context("when decoding") {
      should("consume only a single byte if it is 0 and return None") {
        checkAll(
          Arb.slice(
            byteArrayOf(0),
            alreadyConsumedLength = 0U..128U,
            extraLength = 0U..128U,
          ),
        ) { slice ->
          for (dt in listOf(optUInt8, optUInt32, optStruct, optUInt32V)) {
            shouldNotRaise { dt.decode(slice) }.also { (decoded, remaining) ->
              remaining.size shouldBe slice.size - 1U
              remaining.firstIndex shouldBe slice.firstIndex + 1U
              remaining.lastIndex shouldBe slice.lastIndex
              remaining.hasRemaining shouldBe (slice.size > 1U)

              decoded.shouldBeNone()
            }
          }
        }
      }

      should("consume bytes according to the value type and return Some(value) if the first consumed byte is 1") {
        checkAll(
          Arb.uInt8().flatMap { uint ->
            Arb.slice(
              byteArrayOf(1, *uint.encode()),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to uint }
          },
        ) { (slice, value) ->
          shouldNotRaise { optUInt8.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 2U
            remaining.firstIndex shouldBe slice.firstIndex + 2U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 2U)

            decoded shouldBeSome value
          }
        }

        checkAll(
          Arb.uInt32().flatMap { uint ->
            Arb.slice(
              byteArrayOf(1, *uint.encode()),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to uint }
          },
        ) { (slice, value) ->
          shouldNotRaise { optUInt32.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 5U
            remaining.firstIndex shouldBe slice.firstIndex + 5U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 5U)

            decoded shouldBeSome value
          }
        }

        checkAll(
          Arb.vector(Arb.uInt32(), 4U).flatMap { vector ->
            Arb.slice(
              byteArrayOf(1, *vector.fold(byteArrayOf()) { b, uint -> b + uint.encode() }),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to vector }
          },
        ) { (slice, value) ->
          shouldNotRaise { optUInt32V.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 17U
            remaining.firstIndex shouldBe slice.firstIndex + 17U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 17U)

            decoded shouldBeSome value
          }
        }

        checkAll(
          Arb.struct(Arb.uInt8(), Arb.vector(Arb.uInt32(), 4U)).flatMap { s ->
            Arb.slice(
              byteArrayOf(1, *s.field1.encode(), *s.field2.fold(byteArrayOf()) { b, uint -> b + uint.encode() }),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to s }
          },
        ) { (slice, value) ->
          shouldNotRaise { optStruct.decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 18U
            remaining.firstIndex shouldBe slice.firstIndex + 18U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 18U)

            decoded shouldBeSome value
          }
        }
      }

      should("raise an error if there are no bytes remaining") {
        checkAll(
          Arb.slice(
            byteArrayOf(),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          for (dt in listOf(optUInt8, optUInt32, optStruct, optUInt32V)) {
            shouldRaise<DecoderError.PrematureEndOfStream> {
              dt.decode(slice)
            } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)
          }
        }
      }

      should("raise an error if the first byte is a 1 but there aren't enough bytes remaining for the value") {
        checkAll(
          Arb.slice(
            byteArrayOf(1),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            optUInt8.decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 1U, 0U)
        }

        checkAll(
          Arb.slice(
            Arb.bind(Arb.constant(byteArrayOf(1)), Arb.byteArray(0..3), ByteArray::plus),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            optUInt32.decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 4U, slice.size - 1U)
        }

        checkAll(
          Arb.slice(
            Arb.bind(Arb.constant(byteArrayOf(1)), Arb.byteArray(0..15), ByteArray::plus),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            optUInt32V.decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 16U, slice.size - 1U)
        }

        checkAll(
          Arb.slice(
            Arb.bind(Arb.constant(byteArrayOf(1)), Arb.byteArray(0..16), ByteArray::plus),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            optStruct.decode(slice)
          } shouldBe
            DecoderError.PrematureEndOfStream(
              if (slice.size > 1U) slice.firstIndex + 2U else slice.firstIndex + 1U,
              if (slice.size > 1U) 16U else 1U,
              if (slice.size > 1U) slice.size - 2U else 0U,
            )
        }
      }

      should("raise an error if the first byte is anything but 0 or 1") {
        checkAll(
          Arb.slice(
            Arb.byteArray(1, Arb.byte().filter { it !in 0..1 }),
            alreadyConsumedLength = 0U..128U,
            extraLength = 0U..128U,
          ),
        ) { slice ->
          for (dt in listOf(optUInt8, optUInt32, optStruct, optUInt32V)) {
            shouldRaise<DecoderError.UnknownEnumValue> {
              dt.decode(slice)
            } shouldBe DecoderError.UnknownEnumValue(slice.firstIndex, "Presence", slice.first.toUByte().toUInt())
          }
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have no encodedLength") {
        for (dt in listOf(optUInt8, optUInt32, optStruct, optUInt32V)) {
          dt.encodedLength.shouldBeNull()
        }
      }

      should("have a name of optional<dataType>") {
        optUInt8.name shouldBe "optional<uint8>"
        optUInt32.name shouldBe "optional<uint32>"
        optStruct.name shouldBe "optional<Test>"
        optUInt32V.name shouldBe "optional<uint32[16]>"
      }
    }

    context("optional[dataType]") {
      should("return an optional type of the given type") {
        optional[uint8].shouldBeInstanceOf<OptionalT<*>>().valueType shouldBe uint8
        optional[uint16].shouldBeInstanceOf<OptionalT<*>>().valueType shouldBe uint16

        optional[uint24[V]].shouldBeInstanceOf<OptionalT<*>>().valueType.shouldBeInstanceOf<VectorT<*>>().also {
          it.componentType shouldBe uint24
          it.length.shouldBeInstanceOf<VariableLength>().mod shouldBe 3U
        }

        shouldNotRaise { optional[uint32[4U..16U]] }.shouldBeInstanceOf<OptionalT<*>>().valueType.shouldBeInstanceOf<VectorT<*>>()
          .also {
            it.componentType shouldBe uint32
            it.length.shouldBeInstanceOf<IntervalLength>().also { l ->
              l.range shouldBe 4U..16U
              l.mod shouldBe 4U
            }
          }

        shouldNotRaise {
          optional[
            struct("Test") {
              it.field("uint", uint8)
            },
          ]
        }.shouldBeInstanceOf<OptionalT<*>>().valueType.shouldBeInstanceOf<Struct1T<*>>().also {
          it.member1.also { f ->
            f.type shouldBe uint8
            f.name shouldBe "uint"
          }
        }
      }
    }
  }
})

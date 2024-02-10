package com.github.traderjoe95.mls.codec.type

import com.github.traderjoe95.mls.codec.byteArray
import com.github.traderjoe95.mls.codec.div
import com.github.traderjoe95.mls.codec.error.DecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.codec.error.LengthError
import com.github.traderjoe95.mls.codec.shouldNotRaise
import com.github.traderjoe95.mls.codec.shouldRaise
import com.github.traderjoe95.mls.codec.slice
import com.github.traderjoe95.mls.codec.times
import com.github.traderjoe95.mls.codec.type.struct.struct
import com.github.traderjoe95.mls.codec.uInt16
import com.github.traderjoe95.mls.codec.uInt8
import com.github.traderjoe95.mls.codec.uIntRange
import com.github.traderjoe95.mls.codec.util.shrToByte
import com.github.traderjoe95.mls.codec.util.toBytes
import com.github.traderjoe95.mls.codec.util.uSize
import com.github.traderjoe95.mls.codec.v1Byte
import com.github.traderjoe95.mls.codec.v2Bytes
import com.github.traderjoe95.mls.codec.vector
import io.kotest.core.spec.style.ShouldSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeTypeOf
import io.kotest.property.Arb
import io.kotest.property.arbitrary.bind
import io.kotest.property.arbitrary.choice
import io.kotest.property.arbitrary.constant
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.flatMap
import io.kotest.property.arbitrary.map
import io.kotest.property.arbitrary.pair
import io.kotest.property.arbitrary.uInt
import io.kotest.property.checkAll
import kotlin.experimental.or

class VectorTest : ShouldSpec({
  context("dataType[fixed]") {
    context("when encoding") {
      should("encode a list of elements with the correct length as the concatenation of their encodings") {
        checkAll(Arb.uInt(1U..1024U).flatMap { Arb.vector(Arb.uInt8(), it) }) { v ->
          shouldNotRaise { uint8[v.uSize].encode(v) } shouldBe v.map { it.toByte() }.toByteArray()
        }

        checkAll(Arb.uInt(1U..1024U).flatMap { Arb.vector(Arb.uInt16(), it) }) { v ->
          shouldNotRaise { uint16[2U * v.uSize].encode(v) }.also {
            it.uSize shouldBe 2U * v.uSize
            it shouldBe v.fold(byteArrayOf()) { b, uint -> b + uint.encode() }
          }
        }
      }

      should("raise an error if the list has the wrong length") {
        checkAll(
          Arb.pair(
            Arb.uInt(1U..1024U),
            Arb.vector(Arb.uInt8(), 1U..1024U),
          ).filter { it.first != it.second.uSize },
        ) { (fixed, vector) ->
          shouldRaise<EncoderError.BadLength> { uint8[fixed].encode(vector) }
        }
      }
    }

    context("when decoding") {
      should("consume as many bytes as the length and data type requires") {
        checkAll(
          Arb.uInt(1U..1024U).flatMap { size ->
            Arb.vector(Arb.uInt8(), size).flatMap { vector ->
              Arb.slice(
                vector.map { it.toByte() }.toByteArray(),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to vector }
            }
          },
        ) { (slice, vector) ->
          shouldNotRaise { uint8[vector.uSize].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize)

            decoded shouldBe vector
          }
        }

        checkAll(
          Arb.uInt(1U..1024U).flatMap { size ->
            Arb.vector(Arb.uInt16(), size).flatMap { vector ->
              Arb.slice(
                vector.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { it to vector }
            }
          },
        ) { (slice, vector) ->
          shouldNotRaise { uint16[2U * vector.uSize].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - 2U * vector.uSize
            remaining.firstIndex shouldBe slice.firstIndex + 2U * vector.uSize
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > 2U * vector.uSize)

            decoded shouldBe vector
          }
        }
      }

      should("raise an error if there are less encoded elements than expected") {
        checkAll(
          Arb.uInt(1U..1024U).flatMap { size ->
            Arb.vector(Arb.uInt8(), 0U..<size).flatMap { vector ->
              Arb.slice(
                vector.map { it.toByte() }.toByteArray(),
                alreadyConsumedLength = 0U..128U,
              ).map { it to size }
            }
          },
        ) { (slice, size) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[size].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, size, slice.size)
        }

        checkAll(
          Arb.uInt(1U..1024U).flatMap { size ->
            Arb.vector(Arb.uInt16(), 0U..<size).flatMap { vector ->
              Arb.slice(
                vector.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
                alreadyConsumedLength = 0U..128U,
              ).map { it to size }
            }
          },
        ) { (slice, size) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[2U * size].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 2U * size, slice.size)
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have an encodedLength of fixed") {
        checkAll(Arb.uInt(0x0U..0xFFFFU).filter { it % 4U == 0U }) {
          for (dt in listOf(uint8, uint32)) {
            shouldNotRaise { dt[it] }.encodedLength shouldBe it
          }
        }
      }

      should("have a name of dataType[fixed]") {
        checkAll(Arb.uInt(0x0U..0xFFFFU).filter { it % 4U == 0U }) {
          for (dt in listOf(uint8, uint32)) {
            shouldNotRaise { dt[it] }.name shouldBe "${dt.name}[$it]"
          }
        }
      }
    }

    context("dataType[fixed]") {
      should("return a vector type with a fixed length") {
        checkAll(Arb.uInt(1U..1024U).filter { it % 12U == 0U }) { fixed ->
          shouldNotRaise { uint8[fixed] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint8
            it.length.shouldBeTypeOf<FixedLength>().fixedLength shouldBe fixed
          }

          shouldNotRaise { uint16[fixed] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint16
            it.length.shouldBeTypeOf<FixedLength>().fixedLength shouldBe fixed
          }

          shouldNotRaise { uint24[fixed] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint24
            it.length.shouldBeTypeOf<FixedLength>().fixedLength shouldBe fixed
          }

          shouldNotRaise { uint32[fixed] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint32
            it.length.shouldBeTypeOf<FixedLength>().fixedLength shouldBe fixed
          }
        }
      }

      should("raise an error if dataType does not have a fixed width") {
        checkAll(Arb.uInt()) { fixed ->
          shouldRaise<LengthError.UndefinedLength> {
            uint8[V][fixed]
          } shouldBe LengthError.UndefinedLength("fixed", "uint8<V>")

          shouldRaise<LengthError.UndefinedLength> {
            optional[uint16][fixed]
          } shouldBe LengthError.UndefinedLength("fixed", "optional<uint16>")

          shouldRaise<LengthError.UndefinedLength> {
            struct("Test") {
              it.field("uint8", uint8)
                .field("variable", uint24[V])
            }[fixed]
          } shouldBe LengthError.UndefinedLength("fixed", "Test")
        }
      }
    }
  }

  context("dataType<min..max>") {
    context("when encoding") {
      should(
        "encode a list of elements as the concatenation of their encodings, " +
          "prefixed with a 1-byte length field if the maximum is in 0..0xFF",
      ) {
        checkAll(
          Arb.uIntRange(0U..0xFEU, 1U..0xFFU).flatMap { interval ->
            Arb.vector(Arb.uInt8(), interval).map { it to interval }
          },
        ) { (v, interval) ->
          shouldNotRaise { uint8[interval].encode(v) } shouldBe
            byteArrayOf(
              v.uSize.toByte(),
              *v.map { it.toByte() }.toByteArray(),
            )
        }

        checkAll(
          Arb.uIntRange(0U..0x7FU, 0x8U..0xFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.vector(Arb.uInt16(), interval / 2U).map { it to interval }
          },
        ) { (v, interval) ->
          shouldNotRaise { uint16[interval].encode(v) } shouldBe
            byteArrayOf(
              (v.uSize * 2U).toByte(),
              *v.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
            )
        }
      }

      should(
        "encode a list of elements as the concatenation of their encodings, " +
          "prefixed with a 2-byte length field if the maximum is in 0x100..0xFFFF",
      ) {
        checkAll(
          Arb.uIntRange(0U..0xFFEU, 0x100U..0xFFFU).flatMap { interval ->
            Arb.vector(Arb.uInt8(), interval).map { it to interval }
          },
        ) { (v, interval) ->
          shouldNotRaise { uint8[interval].encode(v) } shouldBe
            byteArrayOf(
              v.uSize shrToByte 8,
              v.uSize.toByte(),
              *v.map { it.toByte() }.toByteArray(),
            )
        }

        checkAll(
          Arb.uIntRange(0U..0x7FEU, 0x100U..0x7FFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.vector(Arb.uInt16(), interval / 2U).map { it to interval }
          },
        ) { (v, interval) ->
          shouldNotRaise { uint16[interval].encode(v) } shouldBe
            byteArrayOf(
              (v.uSize * 2U) shrToByte 8,
              (v.uSize * 2U).toByte(),
              *v.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
            )
        }
      }

      should("raise an error if the list has the wrong length") {
        checkAll(
          Arb.pair(
            Arb.uIntRange(0U..1023U, 1U..1024U),
            Arb.vector(Arb.uInt8(), 0U..1024U),
          ).filter { it.second.uSize !in it.first },
        ) { (interval, vector) ->
          shouldRaise<EncoderError.BadLength> { uint8[interval].encode(vector) }
        }
      }
    }

    context("when decoding") {
      should("consume one length byte and content bytes according to the length if the maximum length is in 0..0xFF") {
        checkAll(
          Arb.uIntRange(0U..0xFEU, 1U..0xFFU).flatMap { interval ->
            Arb.vector(Arb.uInt8(), interval).flatMap { vector ->
              Arb.slice(
                byteArrayOf(vector.uSize.toByte(), *vector.map { it.toByte() }.toByteArray()),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { Triple(it, interval, vector) }
            }
          },
        ) { (slice, interval, vector) ->
          shouldNotRaise { uint8[interval].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize - 1U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize + 1U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize + 1U)

            decoded shouldBe vector
          }
        }

        checkAll(
          Arb.uIntRange(0U..0x7FU, 0x8U..0xFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.vector(Arb.uInt16(), interval / 2U).flatMap { vector ->
              Arb.slice(
                byteArrayOf((vector.uSize * 2U).toByte(), *vector.fold(byteArrayOf()) { b, uint -> b + uint.encode() }),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { Triple(it, interval, vector) }
            }
          },
        ) { (slice, interval, vector) ->
          shouldNotRaise { uint16[interval].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize * 2U - 1U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize * 2U + 1U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize * 2U + 1U)

            decoded shouldBe vector
          }
        }
      }

      should("consume two length bytes and content bytes according to the length if the maximum length is in 0x100..0xFFFF") {
        checkAll(
          Arb.uIntRange(0U..0xFFEU, 0x100U..0xFFFU).flatMap { interval ->
            Arb.vector(Arb.uInt8(), interval).flatMap { vector ->
              Arb.slice(
                byteArrayOf(vector.uSize shrToByte 8, vector.uSize.toByte(), *vector.map { it.toByte() }.toByteArray()),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { Triple(it, interval, vector) }
            }
          },
        ) { (slice, interval, vector) ->
          shouldNotRaise { uint8[interval].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize - 2U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize + 2U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize + 2U)

            decoded shouldBe vector
          }
        }

        checkAll(
          Arb.uIntRange(0U..0x7FEU, 0x100U..0x7FFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.vector(Arb.uInt16(), interval / 2U).flatMap { vector ->
              Arb.slice(
                byteArrayOf(
                  (vector.uSize * 2U) shrToByte 8,
                  (vector.uSize * 2U).toByte(),
                  *vector.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
                ),
                alreadyConsumedLength = 0U..128U,
                extraLength = 0U..128U,
              ).map { Triple(it, interval, vector) }
            }
          },
        ) { (slice, interval, vector) ->
          shouldNotRaise { uint16[interval].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize * 2U - 2U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize * 2U + 2U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize * 2U + 2U)

            decoded shouldBe vector
          }
        }
      }

      should("raise an error if there are no bytes remaining and the maximum length is in 0..0xFF") {
        checkAll(
          Arb.uIntRange(0U..0xFEU, 1U..0xFFU).flatMap { interval ->
            Arb.slice(
              byteArrayOf(),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)
        }

        checkAll(
          Arb.uIntRange(0U..0xFEU, 1U..0xFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.slice(
              byteArrayOf(),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)
        }
      }

      should("raise an error if there are less than two bytes remaining and the maximum length is in 0x100..0xFFFF") {
        checkAll(
          Arb.uIntRange(0U..0xFFFEU, 0x100U..0xFFFFU).flatMap { interval ->
            Arb.slice(
              Arb.byteArray(0..1),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 2U, slice.size)
        }

        checkAll(
          Arb.uIntRange(0U..0xFFFEU, 0x100U..0xFFFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.slice(
              Arb.byteArray(0..1),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 2U, slice.size)
        }
      }

      should("raise an error if there are less than three bytes remaining and the maximum length is in 0x10000..0xFFFFFF") {
        checkAll(
          Arb.uIntRange(0U..0xFFFFFEU, 0x10000U..0xFFFFFFU).flatMap { interval ->
            Arb.slice(
              Arb.byteArray(0..2),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 3U, slice.size)
        }

        checkAll(
          Arb.uIntRange(0U..0xFFFFFEU, 0x10000U..0xFFFFFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.slice(
              Arb.byteArray(0..2),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 3U, slice.size)
        }
      }

      should("raise an error if there are less than four bytes remaining and the maximum length is in 0x1000000..0xFFFFFFFF") {
        checkAll(
          Arb.uIntRange(0U..0xFFFFFFFEU, 0x1000000U..0xFFFFFFFFU).flatMap { interval ->
            Arb.slice(
              Arb.byteArray(0..3),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 4U, slice.size)
        }

        checkAll(
          Arb.uIntRange(0U..0xFFFFFFFEU, 0x1000000U..0xFFFFFFFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.slice(
              Arb.byteArray(0..3),
              alreadyConsumedLength = 0U..128U,
            ).map { it to interval }
          },
        ) { (slice, interval) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 4U, slice.size)
        }
      }

      should("raise an error if there are less bytes remaining than the length field indicates") {
        checkAll(
          Arb.uIntRange(1U..0xFEU, 2U..0xFFU).flatMap { interval ->
            Arb.uInt(interval).flatMap { lengthField ->
              Arb.slice(
                Arb.bind(
                  Arb.constant(lengthField.toBytes(1U)),
                  Arb.byteArray(0..<lengthField.toInt()),
                  ByteArray::plus,
                ),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, interval, lengthField) }
            }
          },
        ) { (slice, interval, lengthField) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, lengthField, slice.size - 1U)
        }

        checkAll(
          Arb.uIntRange(1U..0xFFEU, 0x100U..0xFFFU).flatMap { interval ->
            Arb.uInt(interval).flatMap { lengthField ->
              Arb.slice(
                Arb.bind(
                  Arb.constant(lengthField.toBytes(2U)),
                  Arb.byteArray(0..<lengthField.toInt()),
                  ByteArray::plus,
                ),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, interval, lengthField) }
            }
          },
        ) { (slice, interval, lengthField) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 2U, lengthField, slice.size - 2U)
        }
      }

      should("raise an error if the decoded length falls outside the interval") {
        checkAll(
          Arb.uIntRange(0x10U..0x7EU, 0x11U..0x7FU).flatMap { interval ->
            Arb.choice(
              Arb.uInt(0U..<interval.first),
              Arb.uInt((interval.last + 1U)..0xFFU),
            ).flatMap { lengthField ->
              Arb.slice(
                Arb.bind(Arb.constant(lengthField.toBytes(1U)), Arb.byteArray(lengthField.toInt()), ByteArray::plus),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, interval, lengthField) }
            }
          },
        ) { (slice, interval, lengthField) ->
          shouldRaise<DecoderError.BadLength> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.BadLength(slice.firstIndex, lengthField, interval, 1U)
        }

        checkAll(
          Arb.uIntRange(0x200U..0x7FEU, 0x201U..0x7FFU).flatMap { interval ->
            Arb.choice(
              Arb.uInt(0U..<interval.first),
              Arb.uInt((interval.last + 1U)..0xFFFFU),
            ).flatMap { lengthField ->
              Arb.slice(
                Arb.bind(Arb.constant(lengthField.toBytes(2U)), Arb.byteArray(lengthField.toInt()), ByteArray::plus),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, interval, lengthField) }
            }
          },
        ) { (slice, interval, lengthField) ->
          shouldRaise<DecoderError.BadLength> {
            uint8[interval].decode(slice)
          } shouldBe DecoderError.BadLength(slice.firstIndex, lengthField, interval, 1U)
        }
      }

      should("raise an error if the decoded length is not a multiple of the data type size") {
        checkAll(
          Arb.uIntRange(0x0U..0x7FU, 0x80U..0xFFU).filter { it.first % 2U == 0U && it.last % 2U == 0U }.flatMap { interval ->
            Arb.uInt(interval).filter { it % 2U == 1U }.flatMap { lengthField ->
              Arb.slice(
                Arb.bind(Arb.constant(lengthField.toBytes(1U)), Arb.byteArray(lengthField.toInt()), ByteArray::plus),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, interval, lengthField) }
            }
          },
        ) { (slice, interval, lengthField) ->
          shouldRaise<DecoderError.BadLength> {
            uint16[interval].decode(slice)
          } shouldBe DecoderError.BadLength(slice.firstIndex, lengthField, interval, 2U)
        }

        checkAll(
          Arb.uIntRange(0x0U..0xFFU, 0x100U..0x5555U).filter { it.first % 3U == 0U && it.last % 3U == 0U }.flatMap { interval ->
            Arb.uInt(interval).filter { it % 3U != 0U }.flatMap { lengthField ->
              Arb.slice(
                Arb.bind(Arb.constant(lengthField.toBytes(2U)), Arb.byteArray(lengthField.toInt()), ByteArray::plus),
                alreadyConsumedLength = 0U..128U,
              ).map { Triple(it, interval, lengthField) }
            }
          },
        ) { (slice, interval, lengthField) ->
          shouldRaise<DecoderError.BadLength> {
            uint24[interval].decode(slice)
          } shouldBe DecoderError.BadLength(slice.firstIndex, lengthField, interval, 3U)
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have no encodedLength") {
        checkAll(Arb.uIntRange(0x0U..0x7FFFU, 0x8000U..0xFFFFU).filter { it.first % 4U == 0U && it.last % 4U == 0U }) {
          for (dt in listOf(uint8, uint32)) {
            shouldNotRaise { dt[it] }.encodedLength.shouldBeNull()
          }
        }
      }

      should("have a name of dataType<min..max>") {
        checkAll(Arb.uIntRange(0x0U..0x7FFFU, 0x8000U..0xFFFFU).filter { it.first % 4U == 0U && it.last % 4U == 0U }) {
          for (dt in listOf(uint8, uint32)) {
            shouldNotRaise {
              dt[it]
            }.name shouldBe "${dt.name}<$it>"
          }
        }
      }
    }

    context("dataType[min..max]") {
      should("return a vector type, adjusting for the size of the data type") {
        checkAll(Arb.uIntRange(0U..1023U, 1U..1024U).filter { it.first % 12U == 0U && it.last % 12U == 0U }) { interval ->
          shouldNotRaise { uint8[interval] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint8
            it.length.shouldBeTypeOf<IntervalLength>().range shouldBe interval
          }

          shouldNotRaise { uint16[interval] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint16
            it.length.shouldBeTypeOf<IntervalLength>().range shouldBe interval
          }

          shouldNotRaise { uint24[interval] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint24
            it.length.shouldBeTypeOf<IntervalLength>().range shouldBe interval
          }

          shouldNotRaise { uint32[interval] }.shouldBeInstanceOf<VectorT<*>>().also {
            it.componentType shouldBe uint32
            it.length.shouldBeTypeOf<IntervalLength>().range shouldBe interval
          }
        }
      }

      should("raise an error if dataType does not have a fixed width") {
        checkAll(Arb.uIntRange(0U..1023U, 1U..1024U)) { interval ->
          shouldRaise<LengthError.UndefinedLength> {
            uint8[V][interval]
          } shouldBe LengthError.UndefinedLength("interval", "uint8<V>")

          shouldRaise<LengthError.UndefinedLength> {
            optional[uint16][interval]
          } shouldBe LengthError.UndefinedLength("interval", "optional<uint16>")

          shouldRaise<LengthError.UndefinedLength> {
            struct("Test") {
              it.field("uint8", uint8)
                .field("variable", uint24[V])
            }[interval]
          } shouldBe LengthError.UndefinedLength("interval", "Test")
        }
      }
    }
  }

  context("dataType<V>") {
    context("when encoding") {
      should(
        "encode a list of elements as the concatenation of their encodings, " +
          "prefixed with a 1-byte length field with tag 00 if the length is in 0..0x3F",
      ) {
        checkAll(
          Arb.vector(Arb.uInt8(), v1Byte),
        ) { v ->
          shouldNotRaise { uint8[V].encode(v) } shouldBe
            byteArrayOf(
              v.uSize.toByte(),
              *v.map { it.toByte() }.toByteArray(),
            )
        }

        checkAll(
          Arb.vector(Arb.uInt16(), v1Byte / 2U),
        ) { v ->
          shouldNotRaise { uint16[V].encode(v) } shouldBe
            byteArrayOf(
              (v.uSize * 2U).toByte(),
              *v.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
            )
        }
      }

      should(
        "encode a list of elements as the concatenation of their encodings, " +
          "prefixed with a 2-byte length field with tag 01 if the length is in 0x40..0x3FFF",
      ) {
        checkAll(
          Arb.vector(Arb.uInt8(), v2Bytes),
        ) { v ->
          shouldNotRaise { uint8[V].encode(v) } shouldBe
            byteArrayOf(
              (v.uSize shrToByte 8) or 0x40.toByte(),
              v.uSize.toByte(),
              *v.map { it.toByte() }.toByteArray(),
            )
        }

        checkAll(
          Arb.vector(Arb.uInt16(), v2Bytes / 2U),
        ) { v ->
          shouldNotRaise { uint16[V].encode(v) } shouldBe
            byteArrayOf(
              ((v.uSize * 2U) shrToByte 8) or 0x40.toByte(),
              (v.uSize * 2U).toByte(),
              *v.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
            )
        }
      }
    }

    context("when decoding") {
      should("consume a single length byte if it has tag 00 and then consume as many elements as the length indicates") {
        checkAll(
          Arb.vector(Arb.uInt8(), v1Byte).flatMap { v ->
            Arb.slice(
              byteArrayOf(v.uSize.toByte(), *v.map { it.toByte() }.toByteArray()),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to v }
          },
        ) { (slice, vector) ->
          shouldNotRaise { uint8[V].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize - 1U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize + 1U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize + 1U)

            decoded shouldBe vector
          }
        }

        checkAll(
          Arb.vector(Arb.uInt16(), v1Byte / 2U).flatMap { v ->
            Arb.slice(
              byteArrayOf((v.uSize * 2U).toByte(), *v.fold(byteArrayOf()) { b, uint -> b + uint.encode() }),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to v }
          },
        ) { (slice, vector) ->
          shouldNotRaise { uint16[V].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize * 2U - 1U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize * 2U + 1U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize * 2U + 1U)

            decoded shouldBe vector
          }
        }
      }

      should("consume two length bytes if the first has tag 01 and then consume as many elements as the length indicates") {
        checkAll(
          Arb.vector(Arb.uInt8(), v2Bytes).flatMap { v ->
            Arb.slice(
              byteArrayOf(
                (v.uSize shrToByte 8) or 0x40.toByte(),
                v.uSize.toByte(),
                *v.map { it.toByte() }.toByteArray(),
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to v }
          },
        ) { (slice, vector) ->
          shouldNotRaise { uint8[V].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize - 2U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize + 2U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize + 2U)

            decoded shouldBe vector
          }
        }

        checkAll(
          Arb.vector(Arb.uInt16(), v2Bytes / 2U).flatMap { v ->
            Arb.slice(
              byteArrayOf(
                ((v.uSize * 2U) shrToByte 8) or 0x40.toByte(),
                (v.uSize * 2U).toByte(),
                *v.fold(byteArrayOf()) { b, uint -> b + uint.encode() },
              ),
              alreadyConsumedLength = 0U..128U,
              extraLength = 0U..128U,
            ).map { it to v }
          },
        ) { (slice, vector) ->
          shouldNotRaise { uint16[V].decode(slice) }.also { (decoded, remaining) ->
            remaining.size shouldBe slice.size - vector.uSize * 2U - 2U
            remaining.firstIndex shouldBe slice.firstIndex + vector.uSize * 2U + 2U
            remaining.lastIndex shouldBe slice.lastIndex
            remaining.hasRemaining shouldBe (slice.size > vector.uSize * 2U + 2U)

            decoded shouldBe vector
          }
        }
      }

      should("raise an error if there are no bytes left") {
        checkAll(
          Arb.slice(
            byteArrayOf(),
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)

          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex, 1U, 0U)
        }
      }

      should("raise an error if the first byte has tag 01 and there are no bytes left") {
        checkAll(
          Arb.uInt(v1Byte).flatMap { size ->
            Arb.slice(
              byteArrayOf(size.toByte() or 0x40),
              alreadyConsumedLength = 0U..128U,
            )
          },
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 1U, 0U)

          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 1U, 0U)
        }
      }

      should("raise an error if the first byte has tag 10 and there are less than three bytes left") {
        checkAll(
          Arb.slice(
            Arb.byteArray(1..3).filter { (it[0].toInt() and 0xC0) == 0x80 },
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 3U, slice.size - 1U)

          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint16[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, 3U, slice.size - 1U)
        }
      }

      should("raise an error if the first byte has tag 11") {
        checkAll(
          Arb.slice(
            Arb.byteArray(1).filter { (it[0].toInt() and 0xC0) == 0xC0 },
            alreadyConsumedLength = 0U..128U,
          ),
        ) { slice ->
          shouldRaise<DecoderError.InvalidLengthEncoding> {
            uint8[V].decode(slice)
          } shouldBe DecoderError.InvalidLengthEncoding(slice.firstIndex)

          shouldRaise<DecoderError.InvalidLengthEncoding> {
            uint8[V].decode(slice)
          } shouldBe DecoderError.InvalidLengthEncoding(slice.firstIndex)
        }
      }

      should("raise an error if there are less bytes than the length indicates") {
        checkAll(
          Arb.uInt(v1Byte).filter { it != 0U }.flatMap { size ->
            Arb.slice(
              Arb.bind(Arb.constant(byteArrayOf(size.toByte())), Arb.byteArray(0..<size.toInt()), ByteArray::plus),
              alreadyConsumedLength = 0U..128U,
            ).map { it to size }
          },
        ) { (slice, size) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 1U, size, slice.size - 1U)
        }

        checkAll(
          Arb.uInt(v2Bytes).flatMap { size ->
            Arb.slice(
              Arb.bind(
                Arb.constant(byteArrayOf((size shrToByte 8) or 0x40, size.toByte())),
                Arb.byteArray(0..<size.toInt()),
                ByteArray::plus,
              ),
              alreadyConsumedLength = 0U..128U,
            ).map { it to size }
          },
        ) { (slice, size) ->
          shouldRaise<DecoderError.PrematureEndOfStream> {
            uint8[V].decode(slice)
          } shouldBe DecoderError.PrematureEndOfStream(slice.firstIndex + 2U, size, slice.size - 2U)
        }
      }
    }

    context("should have DataType<V>'s properties") {
      should("have no encodedLength") {
        for (dt in listOf(uint8, uint32, optional[uint24])) {
          dt[V].encodedLength.shouldBeNull()
        }
      }

      should("have a name of dataType<V>") {
        for (dt in listOf(uint8, uint32, optional[uint24])) {
          dt[V].name shouldBe "${dt.name}<V>"
        }
      }
    }

    context("dataType[V]") {
      should("return a vector type with variable length") {
        uint8[V].shouldBeInstanceOf<VectorT<*>>().also {
          it.componentType shouldBe uint8
          it.length.shouldBeInstanceOf<VariableLength>().mod shouldBe 1U
        }

        uint16[V].shouldBeInstanceOf<VectorT<*>>().also {
          it.componentType shouldBe uint16
          it.length.shouldBeInstanceOf<VariableLength>().mod shouldBe 2U
        }

        optional[uint24][V].shouldBeInstanceOf<VectorT<*>>().also {
          it.componentType.shouldBeInstanceOf<OptionalT<*>>().valueType shouldBe uint24
          it.length.shouldBeInstanceOf<VariableLength>().mod.shouldBeNull()
        }
      }
    }
  }
})
